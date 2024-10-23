-module(hctest_producing_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("../../aecontract/include/hard_forks.hrl").
-include("../include/hc_test.hrl").

groups() ->
    [
        {late_producing, [sequence], [
            %% A block mined late by the leader
            %% Make sure that the current leader does not mine within the time slot
            start_two_child_nodes,
            produce_first_epoch,
            produce_1_cc_block,
            spend_txs_late_producing,
            produce_1_cc_block_late,
            verify_consensus_solution_late_block
        ]},
        {producing_two_sequential_blocks, [sequence], [
            %% Mining two valid consecutive blocks should be rejected (because leader is only at a specific height)
            start_two_child_nodes,
            produce_first_epoch
            %%
        ]},
        {bad_block, [sequence], [
            %% - Producing a bad block that does not pass the checks
            %% What are the things we're checking for in the block?
            %% Block can have timestamp not before previous. And height.
            %% Block can be received (gossiped) only within its time window
        ]}
].
