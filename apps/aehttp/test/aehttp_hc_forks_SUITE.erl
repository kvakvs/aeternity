% elp:ignore W0014
-module(aehttp_hc_forks_SUITE).

-import(aecore_suite_utils, [
    http_request/4,
    external_address/0,
    rpc/3,
    rpc/4
]).

-export(
    [
        all/0,
        groups/0,
        suite/0,
        init_per_suite/1,
        end_per_suite/1,
        init_per_group/2,
        end_per_group/2,
        init_per_testcase/2,
        end_per_testcase/2
    ]
).

%% Test cases
-export([
    start_two_child_nodes/1,
    produce_first_epoch/1,
    produce_1_cc_block/1, produce_1_cc_block_late/1, produce_3_cc_blocks/1,
    spend_txs_late_mining/1,
    verify_consensus_solution_late_block/1,
    verify_consensus_solution_netsplit/1
]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("aecontract/include/hard_forks.hrl").
-include("../../aecontract/test/include/aect_sophia_vsn.hrl").

-define(MAIN_STAKING_CONTRACT, "MainStaking").
-define(HC_CONTRACT, "HCElection").
-define(CONSENSUS, hc).
-define(CHILD_EPOCH_LENGTH, 10).
-define(CHILD_BLOCK_TIME, 200).
-define(PARENT_EPOCH_LENGTH, 3).
-define(PARENT_FINALITY, 2).
-define(REWARD_DELAY, 2).

-define(NODE1, dev1).
-define(NODE1_NAME, aecore_suite_utils:node_name(?NODE1)).

-define(NODE2, dev2).
-define(NODE2_NAME, aecore_suite_utils:node_name(?NODE2)).

-define(NODE3, dev3).
-define(NODE3_NAME, aecore_suite_utils:node_name(?NODE3)).

-define(OWNER_PUBKEY, <<42:32/unit:8>>).

-define(PARENT_CHAIN_NODE, aecore_suite_utils:parent_chain_node(1)).
-define(PARENT_CHAIN_NODE_NAME, aecore_suite_utils:node_name(?PARENT_CHAIN_NODE)).
-define(PARENT_CHAIN_NETWORK_ID, <<"local_testnet">>).

-define(DEFAULT_GAS_PRICE, aec_test_utils:min_gas_price()).
-define(INITIAL_STAKE, 1_000_000_000_000_000_000_000_000).

-define(ALICE, {
    <<177, 181, 119, 188, 211, 39, 203, 57, 229, 94, 108, 2, 107, 214, 167, 74, 27, 53, 222, 108, 6,
        80, 196, 174, 81, 239, 171, 117, 158, 65, 91, 102>>,
    <<145, 69, 14, 254, 5, 22, 194, 68, 118, 57, 0, 134, 66, 96, 8, 20, 124, 253, 238, 207, 230,
        147, 95, 173, 161, 192, 86, 195, 165, 186, 115, 251, 177, 181, 119, 188, 211, 39, 203, 57,
        229, 94, 108, 2, 107, 214, 167, 74, 27, 53, 222, 108, 6, 80, 196, 174, 81, 239, 171, 117,
        158, 65, 91, 102>>,
    "Alice"
}).
%% ak_2MGLPW2CHTDXJhqFJezqSwYSNwbZokSKkG7wSbGtVmeyjGfHtm

-define(BOB, {
    <<103, 28, 85, 70, 70, 73, 69, 117, 178, 180, 148, 246, 81, 104, 33, 113, 6, 99, 216, 72, 147,
        205, 210, 210, 54, 3, 122, 84, 195, 62, 238, 132>>,
    <<59, 130, 10, 50, 47, 94, 36, 188, 50, 163, 253, 39, 81, 120, 89, 219, 72, 88, 68, 154, 183,
        225, 78, 92, 9, 216, 215, 59, 108, 82, 203, 25, 103, 28, 85, 70, 70, 73, 69, 117, 178, 180,
        148, 246, 81, 104, 33, 113, 6, 99, 216, 72, 147, 205, 210, 210, 54, 3, 122, 84, 195, 62,
        238, 132>>,
    "Bob"
}).
%% ak_nQpnNuBPQwibGpSJmjAah6r3ktAB7pG9JHuaGWHgLKxaKqEvC

-define(LISA, {
    <<200, 171, 93, 11, 3, 93, 177, 65, 197, 27, 123, 127, 177, 165, 190, 211, 20, 112, 79, 108, 85,
        78, 88, 181, 26, 207, 191, 211, 40, 225, 138, 154>>,
    <<237, 12, 20, 128, 115, 166, 32, 106, 220, 142, 111, 97, 141, 104, 201, 130, 56, 100, 64, 142,
        139, 163, 87, 166, 185, 94, 4, 159, 217, 243, 160, 169, 200, 171, 93, 11, 3, 93, 177, 65,
        197, 27, 123, 127, 177, 165, 190, 211, 20, 112, 79, 108, 85, 78, 88, 181, 26, 207, 191, 211,
        40, 225, 138, 154>>,
    "Lisa"
}).
%% ak_2XNq9oKtThxKLNFGWTaxmLBZPgP7ECEGxL3zK7dTSFh6RyRvaG

-define(DWIGHT, {
    <<8, 137, 159, 99, 139, 175, 27, 58, 77, 11, 191, 52, 198, 199, 7, 50, 133, 195, 184, 219, 148,
        124, 4, 5, 44, 247, 57, 95, 188, 173, 95, 35>>,
    <<107, 251, 189, 176, 92, 221, 4, 46, 56, 231, 137, 117, 181, 8, 124, 14, 212, 150, 167, 53, 95,
        94, 50, 86, 144, 230, 93, 222, 61, 116, 85, 96, 8, 137, 159, 99, 139, 175, 27, 58, 77, 11,
        191, 52, 198, 199, 7, 50, 133, 195, 184, 219, 148, 124, 4, 5, 44, 247, 57, 95, 188, 173, 95,
        35>>,
    %% Parent chain account
    "Dwight"
}).
%% ak_4m5iGyT3AiahzGKCE2fCHVsQYU7FBMDiaMJ1YPxradKsyfCc9

-define(EDWIN, {
    <<212, 212, 169, 78, 149, 148, 138, 221, 156, 80, 4, 156, 9, 139, 144, 114, 243, 122, 20, 103,
        168, 43, 42, 244, 93, 118, 38, 98, 71, 34, 199, 94>>,
    <<81, 177, 15, 108, 16, 183, 128, 229, 4, 114, 166, 227, 47, 125, 145, 21, 68, 196, 185, 115,
        42, 198, 168, 204, 220, 206, 200, 58, 12, 32, 56, 98, 212, 212, 169, 78, 149, 148, 138, 221,
        156, 80, 4, 156, 9, 139, 144, 114, 243, 122, 20, 103, 168, 43, 42, 244, 93, 118, 38, 98, 71,
        34, 199, 94>>,
    %% Parent chain account
    "Edwin"
}).
%% ak_2cjUYDhaKaiyGvuswL6K96ooKZKtFZZEopgxc3hwR2Yqb8SWxd

-define(FORD, {
    <<157, 139, 168, 202, 250, 128, 128, 7, 45, 18, 214, 147, 85, 31, 12, 182, 220, 213, 173, 237,
        6, 147, 239, 41, 183, 214, 34, 113, 100, 122, 208, 14>>,
    <<105, 184, 53, 188, 53, 158, 124, 5, 171, 89, 28, 64, 41, 203, 59, 179, 66, 53, 26, 132, 75,
        116, 139, 24, 228, 4, 200, 223, 25, 224, 76, 127, 157, 139, 168, 202, 250, 128, 128, 7, 45,
        18, 214, 147, 85, 31, 12, 182, 220, 213, 173, 237, 6, 147, 239, 41, 183, 214, 34, 113, 100,
        122, 208, 14>>,
    "Ford"
}).
%% ak_2CPHnpGxYw3T7XdUybxKDFGwtFQY7E5o3wJzbexkzSQ2BQ7caJ

% -define(GENESIS_BENEFICIARY,
%     <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
% ).

all() ->
    [
        {group, group_mining},
        % {group, group_gossip},
        {group, group_netsplit}
        % {group, group_netsplit_eoe}
    ].

groups() ->
    [
        {group_mining, [sequence], [
            %% A block mined late by the leader
            %% Make sure that the current leader does not mine within the time slot
            start_two_child_nodes,
            produce_first_epoch,
            produce_1_cc_block,
            spend_txs_late_mining,
            produce_1_cc_block_late,
            verify_consensus_solution_late_block
        ]},
        % {group_gossip, [sequence], [
        %     %% Blocks gossiped late
        %     %% Make sure that the current leader does not make it into the time slot
        %     start_two_child_nodes,
        %     produce_first_epoch,
        %     delay_leader_gossip
        % ]}
        {group_netsplit, [sequence], [
            %% Create a network split in the middle of a block
            start_two_child_nodes,
            produce_first_epoch,
            start_netsplit,
            produce_3_cc_blocks,
            finish_netsplit,
            verify_consensus_solution_netsplit
        ]}
        % {group_netsplit_eoe, [sequence], [
        %     %% Create a network split in the end of an epoch
        %     start_two_child_nodes,
        %     produce_first_epoch
        % ]}
    ].

%% Test suite TO DO:
%%
%% Malicious (and disfunctional) nodes
%% - Disappearing leader
%% - 51% attack?
%% - Producing multiple blocks in a time slot is not allowed
%%
%% Chain Attacks and Penalties
%%
%% Which activities are to be detected and penalized? Ignore cases which should be detected by the gossiping protocol.
%% - Double spending: Attempting to spend the same funds multiple times
%% - Sybil attack: Creating multiple fake identities to gain disproportionate influence
%%   - Allowed in PoS (or does the random node distribution math say otherwise? TODO: the math)
%% - Eclipse attack: Isolating a node from the rest of the network
%%   - No penalty, should be resolved by the consensus protocol
%% - Long-range attack: Rewriting a long history of the blockchain
%% - Spam transactions: Flooding the network with useless transactions
%%   - There's a cost to posting a txn?]
%% - Invalid block propagation: Spreading blocks that don't follow consensus rules
%%   - Gossiping and consensus protocol should prevent this?
%% - Timejacking: Manipulating a node's time to affect block acceptance
%%   - There should be some sort of time and timeslot verification in the gossiping and consensus protocol
%% - Txn manipulation (address substitution)
%% - Routing attacks: Bad actors can intercept data over the group of network nodes, preventing the chain from reaching consensus.
%%
%% Halting
%% - The chain will stop when there aren't enough online nodes to serve as producers

suite() -> [].

init_per_suite(Config0) ->
    case aect_test_utils:require_at_least_protocol(?CERES_PROTOCOL_VSN) of
        {skip, _} = Skip ->
            Skip;
        ok ->
            {ok, _StartedApps} = application:ensure_all_started(gproc),
            Config = [{symlink_name, "latest.hyperchains"}, {test_module, ?MODULE}] ++ Config0,
            Config1 = aecore_suite_utils:init_per_suite(
                [?NODE1, ?NODE2],
                %% config is rewritten per suite
                #{},
                [],
                Config
            ),
            GenesisProtocol = 1,
            {ok, AccountFileName} =
                aecore_suite_utils:hard_fork_filename(
                    ?PARENT_CHAIN_NODE,
                    Config1,
                    integer_to_list(GenesisProtocol),
                    "accounts_test.json"
                ),
            GenesisProtocolBin = integer_to_binary(GenesisProtocol),
            ParentCfg =
                #{
                    <<"chain">> =>
                        #{
                            <<"persist">> => false,
                            <<"hard_forks">> =>
                                #{
                                    GenesisProtocolBin => #{
                                        <<"height">> => 0, <<"accounts_file">> => AccountFileName
                                    },
                                    integer_to_binary(?CERES_PROTOCOL_VSN) => #{<<"height">> => 1}
                                },
                            <<"consensus">> =>
                                #{<<"0">> => #{<<"type">> => <<"ct_tests">>}}
                        },
                    <<"fork_management">> =>
                        #{<<"network_id">> => ?PARENT_CHAIN_NETWORK_ID},
                    <<"mempool">> => #{<<"nonce_offset">> => 200},
                    <<"mining">> =>
                        #{
                            <<"micro_block_cycle">> => 1,
                            <<"expected_mine_rate">> => 2000,
                            <<"autostart">> => false,
                            <<"beneficiary_reward_delay">> => ?REWARD_DELAY
                        }
                },
            aecore_suite_utils:make_multi(Config1, [?PARENT_CHAIN_NODE]),
            aecore_suite_utils:create_config(?PARENT_CHAIN_NODE, Config1, ParentCfg, []),
            {_ParentPatronPriv, ParentPatronPub} = aecore_suite_utils:sign_keys(?PARENT_CHAIN_NODE),
            ParentPatronPubEnc = aeser_api_encoder:encode(account_pubkey, ParentPatronPub),
            aecore_suite_utils:create_seed_file(
                AccountFileName,
                #{
                    ParentPatronPubEnc =>
                        100000000000000000000000000000000000000000000000000000000000000000000000,
                    encoded_pubkey(?DWIGHT) => 2100000000000000000000000000,
                    encoded_pubkey(?EDWIN) => 3100000000000000000000000000
                }
            ),
            StakingContract = staking_contract_address(),
            ElectionContract = election_contract_address(),
            {ok, SVBinSrc} = aect_test_utils:read_contract("StakingValidator"),
            {ok, MSBinSrc} = aect_test_utils:read_contract(?MAIN_STAKING_CONTRACT),
            {ok, EBinSrc} = aect_test_utils:read_contract(?HC_CONTRACT),
            [
                {staking_contract, StakingContract},
                {election_contract, ElectionContract},
                {contract_src, #{
                    "StakingValidator" => create_stub(binary_to_list(SVBinSrc)),
                    ?MAIN_STAKING_CONTRACT => create_stub(binary_to_list(MSBinSrc)),
                    ?HC_CONTRACT => create_stub(binary_to_list(EBinSrc))
                }}
                | Config1
            ]
    end.

end_per_suite(Config) ->
    catch aecore_suite_utils:stop_node(?NODE1, Config),
    catch aecore_suite_utils:stop_node(?NODE2, Config),
    catch aecore_suite_utils:stop_node(?NODE3, Config),
    catch aecore_suite_utils:stop_node(?PARENT_CHAIN_NODE, Config),
    [
        application:stop(A)
     || A <- lists:reverse(
            proplists:get_value(started_apps, Config, [])
        )
    ],
    ok.

init_per_group(_, Config0) ->
    VM = fate,
    NetworkId = <<"hc">>,
    GenesisStartTime = aeu_time:now_in_msecs(),
    Config = [
        {network_id, NetworkId},
        {genesis_start_time, GenesisStartTime},
        {consensus, ?CONSENSUS}
        | aect_test_utils:init_per_group(VM, Config0)
    ],

    aecore_suite_utils:start_node(?PARENT_CHAIN_NODE, Config),
    aecore_suite_utils:connect(?PARENT_CHAIN_NODE_NAME, []),
    ParentTopHeight = rpc(?PARENT_CHAIN_NODE, aec_chain, top_height, []),
    StartHeight = max(ParentTopHeight, ?PARENT_EPOCH_LENGTH),
    ct:log("Parent chain top height ~p start at ~p", [ParentTopHeight, StartHeight]),
    %%TODO mine less than necessary parent height and test chain starts when height reached
    {ok, _} = mine_key_blocks(
        ?PARENT_CHAIN_NODE_NAME,
        (StartHeight - ParentTopHeight) + ?PARENT_FINALITY
    ),
    [{staker_names, [?ALICE, ?BOB, ?LISA]}, {parent_start_height, StartHeight} | Config].

child_node_config(Node, Stakeholders, CTConfig) ->
    ReceiveAddress = encoded_pubkey(?FORD),
    Pinning = false,
    NodeConfig = node_config(Node, CTConfig, Stakeholders, ReceiveAddress, Pinning),
    build_json_files(?HC_CONTRACT, NodeConfig, CTConfig),
    aecore_suite_utils:create_config(Node, CTConfig, NodeConfig, [{add_peers, true}]).

end_per_group(_Group, Config) ->
    Config1 = with_saved_keys([nodes], Config),
    [
        aecore_suite_utils:stop_node(Node, Config1)
     || {Node, _, _} <- proplists:get_value(nodes, Config1, [])
    ],
    Config1.

%% Here we decide which nodes are started/running
init_per_testcase(start_two_child_nodes, Config) ->
    Config1 =
        [
            {nodes, [
                {?NODE1, ?NODE1_NAME, [?ALICE, ?LISA]},
                {?NODE2, ?NODE2_NAME, [?BOB]}
            ]}
            | Config
        ],
    aect_test_utils:setup_testcase(Config1),
    Config1;
init_per_testcase(sync_third_node, Config) ->
    Config1 = with_saved_keys([nodes], Config),
    Nodes = ?config(nodes, Config1),
    Config2 = lists:keyreplace(
        nodes,
        1,
        Config1,
        {nodes, Nodes ++ [{?NODE3, ?NODE3_NAME, []}]}
    ),
    aect_test_utils:setup_testcase(Config2),
    Config2;
init_per_testcase(_Case, Config) ->
    Config1 = with_saved_keys([nodes], Config),
    aect_test_utils:setup_testcase(Config1),
    Config1.

end_per_testcase(_Case, Config) ->
    {save_config, Config}.

with_saved_keys(Keys, Config) ->
    {_TC, SavedConfig} = ?config(saved_config, Config),
    lists:foldl(
        fun(Key, Conf) ->
            case proplists:get_value(Key, SavedConfig) of
                undefined -> Conf;
                Val -> [{Key, Val} | Conf]
            end
        end,
        lists:keydelete(saved_config, 1, Config),
        Keys
    ).

contract_create_spec(Name, Src, Args, Amount, Nonce, Owner) ->
    {ok, Code} = aect_test_utils:compile_contract(aect_test_utils:sophia_version(), Name),
    Pubkey = aect_contracts:compute_contract_pubkey(Owner, Nonce),
    EncodedPubkey = aeser_api_encoder:encode(contract_pubkey, Pubkey),
    EncodedOwner = aeser_api_encoder:encode(account_pubkey, Owner),
    EncodedCode = aeser_api_encoder:encode(contract_bytearray, Code),
    {ok, CallData} = aect_test_utils:encode_call_data(Src, "init", Args),
    EncodedCallData = aeser_api_encoder:encode(contract_bytearray, CallData),
    VM = aect_test_utils:vm_version(),
    ABI = aect_test_utils:abi_version(),
    Spec = #{
        <<"amount">> => Amount,
        <<"vm_version">> => VM,
        <<"abi_version">> => ABI,
        <<"nonce">> => Nonce,
        <<"code">> => EncodedCode,
        <<"call_data">> => EncodedCallData,
        <<"pubkey">> => EncodedPubkey,
        <<"owner_pubkey">> => EncodedOwner
    },
    Spec.

contract_call_spec(ContractPubkey, Src, Fun, Args, Amount, From, Nonce) ->
    {contract_call_tx, CallTx} =
        aetx:specialize_type(
            contract_call(
                ContractPubkey,
                Src,
                Fun,
                Args,
                Amount,
                From,
                Nonce
            )
        ),
    %% Don't allow named contracts!?
    {contract, ContractPubKey} =
        aeser_id:specialize(aect_call_tx:contract_id(CallTx)),
    Spec =
        #{
            <<"caller">> => aeser_api_encoder:encode(
                account_pubkey,
                aect_call_tx:caller_pubkey(CallTx)
            ),
            <<"nonce">> => aect_call_tx:nonce(CallTx),
            <<"contract_pubkey">> => aeser_api_encoder:encode(contract_pubkey, ContractPubKey),
            <<"abi_version">> => aect_call_tx:abi_version(CallTx),
            <<"fee">> => aect_call_tx:fee(CallTx),
            <<"amount">> => aect_call_tx:amount(CallTx),
            <<"gas">> => aect_call_tx:gas(CallTx),
            <<"gas_price">> => aect_call_tx:gas_price(CallTx),
            <<"call_data">> => aeser_api_encoder:encode(
                contract_bytearray,
                aect_call_tx:call_data(CallTx)
            )
        },
    Spec.

start_netsplit(Config) ->
    ok.

finish_netsplit(Config) ->
    ok.

verify_consensus_solution_netsplit(Config) ->
    %% TODO: verify that the chain split is detected and the correct chain is continued
    %% TODO: Check with the whitepaper the correct behaviour
    ok.

%% Test step: Produce 1 block in the child chain, sync nodes
produce_1_cc_block(Config) ->
    {ok, _KBs} = produce_cc_blocks(Config, 1, undefined),
    {ok, _KB} = wait_same_top([Node || {Node, _, _} <- ?config(nodes, Config)]),
    ok.

%% Test step: Produce 3 blocks in the child chain, sync nodes
produce_3_cc_blocks(Config) ->
    {ok, _KBs} = produce_cc_blocks(Config, 1, undefined),
    {ok, _KB} = wait_same_top([Node || {Node, _, _} <- ?config(nodes, Config)]),
    ok.

%% Test step: Produce 1 block, but late out of their time slot, sync the child chain
produce_1_cc_block_late(Config) ->
    {ok, _KBs} = produce_cc_blocks(Config, 1, late_mining),
    {ok, _KB} = wait_same_top([Node || {Node, _, _} <- ?config(nodes, Config)]),
    ok.

%% Add one transaction to create a micro block
%% The current leader is requested to mine late outside of their time slot
%% The expected result: The late block is not accepted, and the other leader has produced one
spend_txs_late_mining(Config) ->
    Top0 = rpc(?NODE1, aec_chain, top_header, []),
    ct:log("Top before posting spend txs: ~p", [aec_headers:height(Top0)]),
    NetworkId = ?config(network_id, Config),
    {ok, []} = rpc:call(?NODE1_NAME, aec_tx_pool, peek, [infinity]),
    seed_account(pubkey(?ALICE), 100000001 * ?DEFAULT_GAS_PRICE, NetworkId),
    % seed_account(pubkey(?BOB), 100000002 * ?DEFAULT_GAS_PRICE, NetworkId),
    % seed_account(pubkey(?LISA), 100000003 * ?DEFAULT_GAS_PRICE, NetworkId),

    produce_cc_blocks(Config, 1, late_mining),
    {ok, []} = rpc:call(?NODE1_NAME, aec_tx_pool, peek, [infinity]),
    %% TODO check that the actors got their share
    ok.

wait_same_top(Nodes) ->
    wait_same_top(Nodes, 3).

wait_same_top(_Nodes, Attempts) when Attempts < 1 ->
    {error, run_out_of_attempts};
wait_same_top(Nodes, Attempts) ->
    KBs = [rpc(Node, aec_chain, top_block, []) || Node <- Nodes],
    case lists:usort(KBs) of
        [KB] ->
            {ok, KB};
        Diffs ->
            ct:log("Nodes differ: ~p", [Diffs]),
            timer:sleep(?CHILD_BLOCK_TIME div 2),
            wait_same_top(Nodes, Attempts - 1)
    end.

start_two_child_nodes(Config) ->
    [{Node1, NodeName1, Stakers1}, {Node2, NodeName2, Stakers2} | _] = ?config(nodes, Config),
    Env = [{"AE__FORK_MANAGEMENT__NETWORK_ID", binary_to_list(?config(network_id, Config))}],
    child_node_config(Node1, Stakers1, Config),
    aecore_suite_utils:start_node(Node1, Config, Env),
    aecore_suite_utils:connect(NodeName1, []),
    child_node_config(Node2, Stakers2, Config),
    aecore_suite_utils:start_node(Node2, Config, Env),
    aecore_suite_utils:connect(NodeName2, []),
    ok.

empty_parent_block(_Config) ->
    case aect_test_utils:latest_protocol_version() < ?CERES_PROTOCOL_VSN of
        true ->
            {skip, lazy_leader_sync_broken_on_iris};
        false ->
            %% empty_parent_block_(Config)
            {skip, todo}
    end.

produce_first_epoch(Config) ->
    produce_n_epochs(Config, 1).

produce_n_epochs(Config, N) ->
    [{Node1, _, _} | _] = ?config(nodes, Config),
    %% produce blocks
    {ok, Bs} = produce_cc_blocks(Config, N * ?CHILD_EPOCH_LENGTH, undefined),
    %% check producers
    Producers = [aec_blocks:miner(B) || B <- Bs],
    ChildTopHeight = rpc(Node1, aec_chain, top_height, []),
    Leaders = leaders_at_height(Node1, ChildTopHeight, Config),
    ct:log("Bs: ~p  Leaders ~p", [Bs, Leaders]),
    %% Check that all producers are valid leaders
    ?assertEqual([], lists:usort(Producers) -- Leaders),
    %% If we have more than 1 leader, then we should see more than one producer
    %% at least for larger EPOCHs
    ?assert(length(Leaders) > 1, length(Producers) > 1),
    ParentTopHeight = rpc(?PARENT_CHAIN_NODE, aec_chain, top_height, []),
    {ok, ParentBlocks} = get_generations(?PARENT_CHAIN_NODE, 0, ParentTopHeight),
    ct:log("Parent chain blocks ~p", [ParentBlocks]),
    {ok, ChildBlocks} = get_generations(Node1, 0, ChildTopHeight),
    ct:log("Child chain blocks ~p", [ChildBlocks]),
    ok.

leaders_at_height(Node, Height, Config) ->
    {ok, Hash} = rpc(Node, aec_chain_state, get_key_block_hash_at_height, [Height]),
    {ok, Return} = inspect_staking_contract(?ALICE, leaders, Config, Hash),
    [
        begin
            {account_pubkey, K} = aeser_api_encoder:decode(LeaderKey),
            K
        end
     || [LeaderKey, _LeaderStake] <- Return
    ].

inspect_staking_contract(OriginWho, WhatToInspect, Config, TopHash) ->
    {Fun, Args} =
        case WhatToInspect of
            {staking_power, Who} ->
                {"staking_power", [binary_to_list(encoded_pubkey(Who))]};
            {get_validator_state, Who} ->
                {"get_validator_state", [binary_to_list(encoded_pubkey(Who))]};
            get_state ->
                {"get_state", []};
            leaders ->
                {"sorted_validators", []}
        end,
    ContractPubkey = ?config(staking_contract, Config),
    do_contract_call(
        ContractPubkey, src(?MAIN_STAKING_CONTRACT, Config), Fun, Args, OriginWho, TopHash
    ).

do_contract_call(CtPubkey, CtSrc, Fun, Args, Who, TopHash) ->
    F = fun() -> do_contract_call_(CtPubkey, CtSrc, Fun, Args, Who, TopHash) end,
    {T, Res} = timer:tc(F),
    ct:log("Calling contract took ~.2f ms", [T / 1000]),
    Res.

do_contract_call_(CtPubkey, CtSrc, Fun, Args, Who, TopHash) ->
    Tx = contract_call(CtPubkey, CtSrc, Fun, Args, 0, pubkey(Who)),
    {ok, Call} = dry_run(TopHash, Tx),
    decode_consensus_result(Call, Fun, CtSrc).

verify_consensus_solution_late_block(Config) ->
    %% TODO: verify that the late block is not accepted and some other leader stepped in
    ok.

%%%--------------------------------------------------------------------
%%% Helper functions
%%%--------------------------------------------------------------------

contract_call(ContractPubkey, Src, Fun, Args, Amount, From) ->
    %% no contract calls support for parent chain
    Nonce = next_nonce(?NODE1, From),
    contract_call(ContractPubkey, Src, Fun, Args, Amount, From, Nonce).

contract_call(ContractPubkey, Src, Fun, Args, Amount, From, Nonce) ->
    {ok, CallData} = aect_test_utils:encode_call_data(Src, Fun, Args),
    ABI = aect_test_utils:abi_version(),
    TxSpec =
        #{
            caller_id => aeser_id:create(account, From),
            nonce => Nonce,
            contract_id => aeser_id:create(contract, ContractPubkey),
            abi_version => ABI,
            fee => 1000000 * ?DEFAULT_GAS_PRICE,
            amount => Amount,
            gas => 1000000,
            gas_price => ?DEFAULT_GAS_PRICE,
            call_data => CallData
        },
    {ok, Tx} = aect_call_tx:new(TxSpec),
    Tx.

decode_consensus_result(Call, Fun, Src) ->
    ReturnType = aect_call:return_type(Call),
    ReturnValue = aect_call:return_value(Call),
    Res = aect_test_utils:decode_call_result(Src, Fun, ReturnType, ReturnValue),
    {ReturnType, Res}.

next_nonce(Node, Pubkey) ->
    case rpc(Node, aec_next_nonce, pick_for_account, [Pubkey, max]) of
        {ok, NextNonce} -> NextNonce;
        {error, account_not_found} -> 1
    end.
pubkey({Pubkey, _, _}) -> Pubkey.

privkey({_, Privkey, _}) -> Privkey.

encoded_pubkey(Who) ->
    aeser_api_encoder:encode(account_pubkey, pubkey(Who)).

src(ContractName, Config) ->
    Srcs = ?config(contract_src, Config),
    maps:get(ContractName, Srcs).

build_json_files(ElectionContract, NodeConfig, CTConfig) ->
    Pubkey = ?OWNER_PUBKEY,
    {_PatronPriv, PatronPub} = aecore_suite_utils:sign_keys(?NODE1),
    ct:log("Patron is ~p", [aeser_api_encoder:encode(account_pubkey, PatronPub)]),
    EncodePub =
        fun(P) ->
            binary_to_list(aeser_api_encoder:encode(account_pubkey, P))
        end,
    %% create staking contract

    %% 1 mln AE
    MinValidatorAmt = integer_to_list(trunc(math:pow(10, 18) * math:pow(10, 6))),
    %% 1 AE
    MinStakeAmt = integer_to_list(trunc(math:pow(10, 18))),
    MinStakePercent = "30",
    OnlineDelay = "0",
    StakeDelay = "0",
    UnstakeDelay = "0",
    #{<<"pubkey">> := StakingValidatorContract} =
        C0 =
        contract_create_spec(
            "StakingValidator",
            src("StakingValidator", CTConfig),
            [EncodePub(Pubkey), UnstakeDelay],
            0,
            1,
            Pubkey
        ),
    {ok, ValidatorPoolAddress} = aeser_api_encoder:safe_decode(
        contract_pubkey,
        StakingValidatorContract
    ),
    %% assert assumption
    ValidatorPoolAddress = validator_pool_contract_address(),
    MSSrc = src(?MAIN_STAKING_CONTRACT, CTConfig),
    #{
        <<"pubkey">> := StakingContractPubkey,
        <<"owner_pubkey">> := ContractOwner
    } =
        SC =
        contract_create_spec(
            ?MAIN_STAKING_CONTRACT,
            MSSrc,
            [
                binary_to_list(StakingValidatorContract),
                MinValidatorAmt,
                MinStakePercent,
                MinStakeAmt,
                OnlineDelay,
                StakeDelay,
                UnstakeDelay
            ],
            0,
            2,
            Pubkey
        ),
    {ok, StakingAddress} = aeser_api_encoder:safe_decode(
        contract_pubkey,
        StakingContractPubkey
    ),
    %% assert assumption
    StakingAddress = staking_contract_address(),
    %% create election contract
    #{
        <<"pubkey">> := ElectionContractPubkey,
        <<"owner_pubkey">> := ContractOwner
    } =
        EC =
        contract_create_spec(
            ElectionContract,
            src(ElectionContract, CTConfig),
            [binary_to_list(StakingContractPubkey)],
            0,
            3,
            Pubkey
        ),
    {ok, ElectionAddress} = aeser_api_encoder:safe_decode(
        contract_pubkey,
        ElectionContractPubkey
    ),
    %% assert assumption
    ElectionAddress = election_contract_address(),
    {ok, SCId} = aeser_api_encoder:safe_decode(
        contract_pubkey,
        StakingContractPubkey
    ),
    Call1 =
        contract_call_spec(
            SCId,
            MSSrc,
            "new_validator",
            [],
            ?INITIAL_STAKE,
            pubkey(?ALICE),
            1
        ),
    Call2 =
        contract_call_spec(
            SCId,
            MSSrc,
            "new_validator",
            [],
            ?INITIAL_STAKE,
            pubkey(?BOB),
            1
        ),
    Call3 =
        contract_call_spec(
            SCId,
            MSSrc,
            "new_validator",
            [],
            ?INITIAL_STAKE,
            pubkey(?LISA),
            1
        ),
    Call4 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_online",
            [],
            0,
            pubkey(?ALICE),
            2
        ),
    Call5 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_online",
            [],
            0,
            pubkey(?BOB),
            2
        ),
    Call6 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_online",
            [],
            0,
            pubkey(?LISA),
            2
        ),
    Call7 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_validator_name",
            ["\"Alice\""],
            0,
            pubkey(?ALICE),
            3
        ),
    Call8 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_validator_name",
            ["\"Bob\""],
            0,
            pubkey(?BOB),
            3
        ),
    Call9 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_validator_name",
            ["\"Lisa\""],
            0,
            pubkey(?LISA),
            3
        ),
    Call10 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_validator_description",
            [
                "\"Alice is a really awesome validator and she had set a description of her great service to the work.\""
            ],
            0,
            pubkey(?ALICE),
            4
        ),
    Call11 =
        contract_call_spec(
            SCId,
            MSSrc,
            "set_validator_avatar_url",
            ["\"https://aeternity.com/images/aeternity-logo.svg\""],
            0,
            pubkey(?ALICE),
            5
        ),

    Call12 =
        contract_call_spec(
            ElectionAddress,
            src(ElectionContract, CTConfig),
            "init_epochs",
            [integer_to_list(?CHILD_EPOCH_LENGTH)],
            0,
            ?OWNER_PUBKEY,
            4
        ),
    %% create a BRI validator in the contract so they can receive
    %% rewards as well
    %% TODO: discuss how we want to tackle this:
    %%  A) require the BRI account to be validator
    %%  B) allow pending stake in the contract that is not allocated
    %%  yet
    %%  C) something else
    %% Call12 =
    %%     contract_call_spec(SCId, MSSrc,
    %%                         "new_validator", [],
    %%                         ?INITIAL_STAKE, BRIPub, 1),
    %% Call13 =
    %%     contract_call_spec(SCId, MSSrc,
    %%                         "set_validator_description",
    %%                         ["\"This validator is offline. She can never become a leader. She has no name set. She is receiving the BRI rewards\""],
    %%                         0, BRIPub, 2),
    %% keep the BRI offline
    AllCalls = [
        Call1,
        Call2,
        Call3,
        Call4,
        Call5,
        Call6,
        Call7,
        Call8,
        Call9,
        Call10,
        Call11,
        Call12
    ],
    ProtocolBin = integer_to_binary(aect_test_utils:latest_protocol_version()),
    #{
        <<"chain">> := #{
            <<"hard_forks">> := #{
                ProtocolBin := #{
                    <<"contracts_file">> := ContractsFileName,
                    <<"accounts_file">> := AccountsFileName
                }
            }
        }
    } = NodeConfig,
    aecore_suite_utils:create_seed_file(
        ContractsFileName,
        #{<<"contracts">> => [C0, SC, EC], <<"calls">> => AllCalls}
    ),
    aecore_suite_utils:create_seed_file(
        AccountsFileName,
        #{
            <<"ak_2evAxTKozswMyw9kXkvjJt3MbomCR1nLrf91BduXKdJLrvaaZt">> =>
                1000000000000000000000000000000000000000000000000,
            encoded_pubkey(?ALICE) => 2100000000000000000000000000,
            encoded_pubkey(?BOB) => 3100000000000000000000000000,
            encoded_pubkey(?LISA) => 4100000000000000000000000000
        }
    ),
    ok.

node_config(Node, CTConfig, PotentialStakers, ReceiveAddress, ProducingCommitments) ->
    NetworkId = ?config(network_id, CTConfig),
    GenesisStartTime = ?config(genesis_start_time, CTConfig),
    Stakers = lists:map(
        fun(HCWho) ->
            %% TODO: discuss key management
            HCPriv = list_to_binary(aeu_hex:bin_to_hex(privkey(HCWho))),
            #{
                <<"hyper_chain_account">> => #{
                    <<"pub">> => encoded_pubkey(HCWho), <<"priv">> => HCPriv
                }
            }
        end,
        PotentialStakers
    ),
    ConsensusType = <<"hyper_chain">>,
    Port = aecore_suite_utils:external_api_port(?PARENT_CHAIN_NODE),
    SpecificConfig =
        #{
            <<"parent_chain">> =>
                #{
                    <<"start_height">> => ?config(parent_start_height, CTConfig),
                    <<"finality">> => ?PARENT_FINALITY,
                    <<"parent_generation">> => ?PARENT_EPOCH_LENGTH,
                    <<"consensus">> =>
                        #{
                            <<"type">> => <<"AE2AE">>,
                            <<"network_id">> => ?PARENT_CHAIN_NETWORK_ID,
                            <<"spend_address">> => ReceiveAddress,
                            <<"fee">> => 100000000000000,
                            <<"amount">> => 9700
                        },
                    <<"polling">> =>
                        #{
                            <<"fetch_interval">> => 100,
                            <<"cache_size">> => 10,
                            <<"nodes">> => [
                                iolist_to_binary(
                                    io_lib:format("http://test:Pass@127.0.0.1:~p", [Port])
                                )
                            ]
                        },
                    <<"producing_commitments">> => ProducingCommitments
                },
            <<"genesis_start_time">> => GenesisStartTime,
            <<"child_epoch_length">> => ?CHILD_EPOCH_LENGTH,
            <<"child_block_time">> => ?CHILD_BLOCK_TIME
        },
    Protocol = aect_test_utils:latest_protocol_version(),
    {ok, ContractFileName} = aecore_suite_utils:hard_fork_filename(
        Node, CTConfig, integer_to_list(Protocol), binary_to_list(NetworkId) ++ "_contracts.json"
    ),
    {ok, AccountFileName} = aecore_suite_utils:hard_fork_filename(
        Node, CTConfig, integer_to_list(Protocol), binary_to_list(NetworkId) ++ "_accounts.json"
    ),
    #{
        <<"chain">> =>
            #{
                <<"persist">> => false,
                <<"hard_forks">> => #{
                    integer_to_binary(Protocol) => #{
                        <<"height">> => 0,
                        <<"contracts_file">> => ContractFileName,
                        <<"accounts_file">> => AccountFileName
                    }
                },
                <<"consensus">> =>
                    #{
                        <<"0">> => #{
                            <<"type">> => ConsensusType,
                            <<"config">> =>
                                maps:merge(
                                    #{
                                        <<"election_contract">> => aeser_api_encoder:encode(
                                            contract_pubkey, election_contract_address()
                                        ),
                                        <<"rewards_contract">> => aeser_api_encoder:encode(
                                            contract_pubkey, staking_contract_address()
                                        ),
                                        <<"contract_owner">> => aeser_api_encoder:encode(
                                            account_pubkey, ?OWNER_PUBKEY
                                        ),
                                        <<"expected_key_block_rate">> => 2000,
                                        <<"stakers">> => Stakers
                                    },
                                    SpecificConfig
                                )
                        }
                    }
            },
        <<"fork_management">> =>
            #{<<"network_id">> => <<"this_will_be_overwritten_runtime">>},
        <<"logging">> => #{<<"level">> => <<"debug">>},
        <<"sync">> => #{<<"ping_interval">> => 5000},
        <<"http">> => #{<<"endpoints">> => #{<<"hyperchain">> => true}},
        <<"mining">> =>
            #{
                <<"micro_block_cycle">> => 1,
                <<"autostart">> => false,
                %%<<"autostart">> => ProducingCommitments,
                <<"beneficiary_reward_delay">> => ?REWARD_DELAY
                %% this relies on certain nonce numbers
            }
    }.

validator_pool_contract_address() ->
    aect_contracts:compute_contract_pubkey(?OWNER_PUBKEY, 1).

staking_contract_address() ->
    aect_contracts:compute_contract_pubkey(?OWNER_PUBKEY, 2).

election_contract_address() ->
    aect_contracts:compute_contract_pubkey(?OWNER_PUBKEY, 3).

%% Increase the child chain with a number of key blocks. Automatically add key blocks on parent chain and
%% if there are Txs, put them in a micro block.
%% SpecialBehaviour parameter is used to change the mining behaviour:
%% - undefined: mine blocks normally
%% - late_mining: mine blocks on the child chain after the time slot has expired
-type ct_config() :: proplists:proplist().
-type produce_special_behaviour() :: undefined | late_mining.
-spec produce_cc_blocks(
    Config :: ct_config(),
    BlocksCnt :: pos_integer(),
    SpecialBehaviour :: produce_special_behaviour()
) -> ok.
produce_cc_blocks(Config, BlocksCnt, SpecialBehaviour) when is_atom(SpecialBehaviour) ->
    [{Node, _, _} | _] = ?config(nodes, Config),
    TopHeight = rpc(Node, aec_chain, top_height, []),
    {ok, #{epoch := Epoch, first := First, last := Last, length := L} = Info} =
        rpc(?NODE1, aec_chain_hc, epoch_info, [TopHeight]),
    ct:log("EpochInfo ~p", [Info]),

    %% At end of BlocksCnt child epoch approaches approx:
    CBAfterEpoch = BlocksCnt - (Last - TopHeight),
    ScheduleUpto = Epoch + 1 + (CBAfterEpoch div L),
    ParentTopHeight = rpc(?PARENT_CHAIN_NODE, aec_chain, top_height, []),
    ct:log("P@~p C@~p for next ~p child blocks", [ParentTopHeight, TopHeight, BlocksCnt]),

    %% Spread parent blocks over BlocksCnt
    ParentProduce =
        lists:append([
            spread(
                ?PARENT_EPOCH_LENGTH,
                TopHeight,
                [{CH, 0} || CH <- lists:seq(First + E * L, Last + E * L)]
            )
         || E <- lists:seq(0, ScheduleUpto - Epoch)
        ]),
    %% Last parameter steers where in Child epoch parent block is produced
    produce_cc_blocks_(Config, BlocksCnt, ParentProduce, SpecialBehaviour).

-spec produce_cc_blocks_(
    Config :: ct_config(),
    BlocksCnt :: pos_integer(),
    ParentProduce :: list(),
    SpecialBehaviour :: produce_special_behaviour()
) -> ok.
produce_cc_blocks_(Config, BlocksCnt, ParentProduce, SpecialBehaviour) ->
    [{Node1, _, _} | _] = ?config(nodes, Config),

    %% The previous production ended with wait_same_top, so asking first node is sufficient
    TopHeight = rpc(Node1, aec_chain, top_height, []),

    %% assert that the parent chain is not mining
    ?assertEqual(stopped, rpc:call(?PARENT_CHAIN_NODE_NAME, aec_conductor, get_mining_state, [])),
    ct:log("parent produce ~p", [ParentProduce]),

    case SpecialBehaviour of
        undefined -> ok;
        late_mining ->
            ct:log("Mining ~p blocks 3s late", []),
            timer:sleep(3_000)
    end,
    NewTopHeight = produce_to_cc_height(Config, TopHeight, TopHeight + BlocksCnt, ParentProduce),
    wait_same_top([Node || {Node, _, _} <- ?config(nodes, Config)]),
    get_generations(Node1, TopHeight + 1, NewTopHeight).

%% It seems we automatically produce child chain blocks in the background
-spec produce_to_cc_height(
    Config :: ct_config(),
    TopHeight :: non_neg_integer(),
    GoalHeight :: non_neg_integer(),
    ParentProduce :: list()
) ->
    non_neg_integer().
produce_to_cc_height(Config, TopHeight, GoalHeight, ParentProduce) ->
    NodeNames = [Name || {_, Name, _} <- ?config(nodes, Config)],
    BlocksNeeded = GoalHeight - TopHeight,
    case BlocksNeeded > 0 of
        false ->
            TopHeight;
        true ->
            NewParentProduce =
                case ParentProduce of
                    [{CH, PBs} | PRest] when CH == TopHeight + 1 ->
                        mine_key_blocks(?PARENT_CHAIN_NODE_NAME, PBs),
                        PRest;
                    PP ->
                        PP
                end,
            KeyBlock =
                case rpc:call(hd(NodeNames), aec_tx_pool, peek, [infinity]) of
                    {ok, []} ->
                        {ok, [{N, Block}]} = mine_cc_blocks(NodeNames, 1),
                        ct:log("CC ~p mined block: ~p", [N, Block]),
                        Block;
                    {ok, _Txs} ->
                        {ok, [{N1, KB}, {N2, MB}]} = mine_cc_blocks(NodeNames, 2),
                        ?assertEqual(key, aec_blocks:type(KB)),
                        ?assertEqual(micro, aec_blocks:type(MB)),
                        ct:log("CC ~p mined block: ~p", [N1, KB]),
                        ct:log("CC ~p mined micro block: ~p", [N2, MB]),
                        KB
                end,
            Producer = get_block_producer_name(?config(staker_names, Config), KeyBlock),
            ct:log("~p produced CC block at height ~p", [Producer, aec_blocks:height(KeyBlock)]),
            produce_to_cc_height(Config, TopHeight + 1, GoalHeight, NewParentProduce)
    end.

mine_cc_blocks(NodeNames, N) ->
    aecore_suite_utils:hc_mine_blocks(NodeNames, N).

get_generations(Node, FromHeight, ToHeight) ->
    ReversedBlocks =
        lists:foldl(
            fun(Height, Accum) ->
                case rpc(Node, aec_chain, get_generation_by_height, [Height, forward]) of
                    {ok, #{key_block := KB, micro_blocks := MBs}} ->
                        ReversedGeneration = lists:reverse(MBs) ++ [KB],
                        ReversedGeneration ++ Accum;
                    error ->
                        error({failed_to_fetch_generation, Height})
                end
            end,
            [],
            lists:seq(FromHeight, ToHeight)
        ),
    {ok, lists:reverse(ReversedBlocks)}.

mine_key_blocks(ParentNodeName, NumParentBlocks) ->
    {ok, _} = aecore_suite_utils:mine_micro_block_emptying_mempool_or_fail(ParentNodeName),
    {ok, KBs} = aecore_suite_utils:mine_key_blocks(ParentNodeName, NumParentBlocks),
    ct:log("Parent block mined ~p ~p number: ~p", [KBs, ParentNodeName, NumParentBlocks]),
    {ok, KBs}.

%get_block_producer_name(Parties, Node, Height) ->
%    Producer = get_block_producer(Node, Height),
%    case lists:keyfind(Producer, 1, Parties) of
%        false -> Producer;
%        {_, _, Name} -> Name
%    end.

get_block_producer_name(Parties, Block) ->
    Producer = aec_blocks:miner(Block),
    case lists:keyfind(Producer, 1, Parties) of
        false -> Producer;
        {_, _, Name} -> Name
    end.

spread(_, _, []) ->
    [];
spread(0, TopHeight, Spread) ->
    [{CH, N} || {CH, N} <- Spread, N /= 0, CH > TopHeight];
%spread(N, TopHeight, [{CH, K} | Spread]) when length(Spread) < N ->
%    %% Take speed first (not realistic), then fill rest
%    spread(0, TopHeight, [{CH, K + N - length(Spread)} | [ {CH2, X+1} || {CH2, X} <- Spread]]);
spread(N, TopHeight, Spread) when N rem 2 == 0 ->
    {Left, Right} = lists:split(length(Spread) div 2, Spread),
    spread(N div 2, TopHeight, Left) ++ spread(N div 2, TopHeight, Right);
spread(N, TopHeight, Spread) when N rem 2 == 1 ->
    {Left, [{Middle, K} | Right]} = lists:split(length(Spread) div 2, Spread),
    spread(N div 2, TopHeight, Left) ++ [{Middle, K + 1} || Middle > TopHeight] ++
        spread(N div 2, TopHeight, Right).

create_stub(ContractFile) ->
    create_stub(ContractFile, []).

create_stub(ContractFile, Opts) ->
    {ok, Enc} = aeso_aci:contract_interface(json, ContractFile, Opts ++ [{no_code, true}]),
    {ok, Stub} = aeso_aci:render_aci_json(Enc),
    binary_to_list(Stub).

elected_leader_did_not_show_up(Config) ->
    case aect_test_utils:latest_protocol_version() < ?CERES_PROTOCOL_VSN of
        true ->
            {skip, lazy_leader_sync_broken_on_iris};
        false ->
            elected_leader_did_not_show_up_(Config)
    end.

elected_leader_did_not_show_up_(Config) ->
    %% stop the block producer
    aecore_suite_utils:stop_node(?NODE1, Config),
    TopHeader0 = rpc(?NODE2, aec_chain, top_header, []),
    {TopHeader0, TopHeader0} = {rpc(?NODE3, aec_chain, top_header, []), TopHeader0},
    ct:log("Starting test at (child chain): ~p", [TopHeader0]),
    %% produce a block on the parent chain
    produce_cc_blocks(Config, 1, undefined),
    {ok, KB} = wait_same_top([?NODE2, ?NODE3]),
    0 = aec_blocks:difficulty(KB),
    TopHeader1 = rpc(?NODE3, aec_chain, top_header, []),
    ct:log("Lazy header: ~p", [TopHeader1]),
    TopHeader1 = rpc(?NODE2, aec_chain, top_header, []),
    NetworkId = ?config(network_id, Config),
    Env = [{"AE__FORK_MANAGEMENT__NETWORK_ID", binary_to_list(NetworkId)}],
    aecore_suite_utils:start_node(?NODE1, Config, Env),
    aecore_suite_utils:connect(?NODE1_NAME, []),
    produce_cc_blocks(Config, 1, undefined),
    {ok, _} = wait_same_top([?NODE1, ?NODE3]),
    %% Give NODE1 a moment to finalize sync and post commitments
    timer:sleep(2000),
    produce_cc_blocks(Config, 1, undefined),
    {ok, _KB1} = wait_same_top([Node || {Node, _, _} <- ?config(nodes, Config)]),
    {ok, _} = produce_cc_blocks(Config, 10, undefined),
    {ok, _KB2} = wait_same_top([Node || {Node, _, _} <- ?config(nodes, Config)]),
    ok.

dry_run(TopHash, Tx) ->
    case rpc(?NODE1, aec_dry_run, dry_run, [TopHash, [], [{tx, Tx}]]) of
        {error, _} = Err -> Err;
        {ok, {[{contract_call_tx, {ok, Call}}], _Events}} -> {ok, Call}
    end.

seed_account(RecpipientPubkey, Amount, NetworkId) ->
    seed_account(?NODE1, RecpipientPubkey, Amount, NetworkId).

seed_account(Node, RecipientPubkey, Amount, NetworkId) ->
    NodeName = aecore_suite_utils:node_name(Node),
    {PatronPriv, PatronPub} = aecore_suite_utils:sign_keys(Node),
    Nonce = next_nonce(Node, PatronPub),
    Params =
        #{
            sender_id => aeser_id:create(account, PatronPub),
            recipient_id => aeser_id:create(account, RecipientPubkey),
            amount => Amount,
            fee => 30000 * ?DEFAULT_GAS_PRICE,
            nonce => Nonce,
            payload => <<>>
        },
    ct:log("Preparing a spend tx: ~p", [Params]),
    {ok, Tx} = aec_spend_tx:new(Params),
    SignedTx = sign_tx(Tx, PatronPriv, NetworkId),
    ok = rpc:call(NodeName, aec_tx_pool, push, [SignedTx, tx_received]),
    {ok, SignedTx}.

%% usually we would use aec_test_utils:sign_tx/3. This function is being
%% executed in the context of the CT test and uses the corresponding
%% network_id. Since the network_id of the HC node is different, we must sign
%% the tx using the test-specific network_id
sign_tx(Tx, Privkey, NetworkId) ->
    Bin0 = aetx:serialize_to_binary(Tx),
    %% since we are in CERES context, we sign th hash
    Bin = aec_hash:hash(signed_tx, Bin0),
    BinForNetwork = <<NetworkId/binary, Bin/binary>>,
    Signatures = [enacl:sign_detached(BinForNetwork, Privkey)],
    aetx_sign:new(Tx, Signatures).
