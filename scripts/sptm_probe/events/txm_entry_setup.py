# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Txm entry setup event handlers extracted from the original probe callback."""


def prepare_context_entry(run, event_state):
    event_state.stack = run.FC_XNU_TXM_CONTEXT_STACK
    event_state.expected_states = [
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x04, sp=event_state.stack,
             regs={0: event_state.stack}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x08, sp=event_state.stack, regs={0: 1}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x0c, sp=event_state.stack, regs={0: 1}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x10, sp=event_state.stack, regs={0: 1}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x14, sp=event_state.stack,
             regs={0: 1, 8: event_state.stack}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x18, sp=event_state.stack,
             regs={0: 1, 8: 0}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x28, sp=event_state.stack,
             regs={0: 1, 8: 0}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x2c, sp=event_state.stack,
             regs={0: 1, 8: event_state.stack}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x30, sp=event_state.stack,
             regs={0: 1, 8: event_state.stack}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x34, sp=event_state.stack,
             regs={0: 1, 8: event_state.stack + run.PAGE}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x38, sp=event_state.stack,
             regs={0: 1, 8: event_state.stack + run.PAGE - 0x400}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x3c,
             sp=event_state.stack + run.PAGE - 0x400,
             regs={0: 1, 8: event_state.stack + run.PAGE - 0x400}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x40,
             sp=event_state.stack + run.PAGE - 0x400,
             regs={0: 1, 8: event_state.stack + run.PAGE - 0x400 + 0x58}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x44,
             sp=event_state.stack + run.PAGE - 0x400,
             regs={0: 1, 8: event_state.stack + run.PAGE - 0x400 + 0x58, 9: 0}),
        dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x48,
             sp=event_state.stack + run.PAGE - 0x400,
             regs={0: 1, 8: event_state.stack + run.PAGE - 0x400 + 0x58,
                   9: 0, 10: 1}),
    ]
    for event_state.state_index, event_state.state in enumerate(event_state.expected_states):
        event_state.state['spsr'] = (0x13c0 if event_state.state_index < 2 else 0x200013c0)
    if event_state.claim:
        event_state.expected_states.append(dict(
            pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x4c,
            sp=event_state.stack + run.PAGE - 0x400, spsr=0x200013c0,
            regs={0: 1, 8: event_state.stack + run.PAGE - 0x400 + 0x58,
                  9: 0, 10: 1},
            memory={'claim': '01'}))
    if event_state.metadata:
        event_state.frame = event_state.stack + run.PAGE - 0x400
        event_state.common = {0: 1, 8: event_state.frame + 0x58, 9: 0, 10: 1}
        event_state.expected_states.extend([
            dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x5c,
                 sp=event_state.frame, spsr=0x200013c0,
                 regs=dict(event_state.common), memory={'claim': '01'}),
            dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x60,
                 sp=event_state.frame, spsr=0x200013c0,
                 regs=dict(event_state.common),
                 memory={'claim': '01', 'zero_word': '00000000'}),
            dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x64,
                 sp=event_state.frame, spsr=0x200013c0,
                 regs=dict(event_state.common),
                 memory={'claim': '01', 'zero_word': '00000000',
                         'zero_byte': '00'}),
            dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x68,
                 sp=event_state.frame, spsr=0x200013c0,
                 regs={0: 1, 8: 1, 9: 0, 10: 1},
                 memory={'claim': '01', 'zero_word': '00000000',
                         'zero_byte': '00'}),
            dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x6c,
                 sp=event_state.frame, spsr=0x200013c0,
                 regs={0: 1, 8: 1, 9: 0, 10: 1},
                 memory={'state': '01', 'claim': '01',
                         'zero_word': '00000000',
                         'zero_byte': '00'}),
        ])
    if event_state.x18_branch:
        event_state.expected_states.append(dict(
            pc=run.FC_XNU_TXM_CONTEXT_TARGET + 0x7c,
            sp=event_state.frame, spsr=0x200013c0,
            regs={0: 1, 8: 1, 9: 0, 10: 1},
            memory={'state': '01', 'claim': '01',
                    'zero_word': '00000000',
                    'zero_byte': '00'}))
    if event_state.outbound:
        event_state.outbound_state = dict(
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET,
            sp=event_state.frame, spsr=0x200013c0,
            regs={0: 1, 8: 1, 9: 0, 10: 1},
            memory={'state': '01', 'claim': '01',
                    'zero_word': '00000000',
                    'zero_byte': '00'})
        if event_state.handler_boundary is not None:
            event_state.outbound_state['capture_regs'] = tuple(range(30))
        event_state.expected_states.append(event_state.outbound_state)
    if event_state.handler_boundary is not None:
        event_state.expected_states.extend([
            dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 4,
                 sp=event_state.frame, spsr=0x200013c0,
                 regs={0: 1, 8: 1, 9: 0, 10: 1},
                 capture_regs=(30,),
                 same_captured_regs=tuple(range(30)),
                 memory={'state': '01', 'claim': '01',
                         'zero_word': '00000000',
                         'zero_byte': '00'}),
            dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 8,
                 sp=event_state.frame - 0x70, spsr=0x200013c0,
                 regs={0: 1, 8: 1, 9: 0, 10: 1},
                 same_captured_regs=tuple(range(31)),
                 memory={'state': '01', 'claim': '01',
                         'zero_word': '00000000',
                         'zero_byte': '00'}),
        ])
    if event_state.handler_boundary in (
            'register-saves', 'local-setup', 'validator-entry',
            'validator-trace', 'response-trace',
            'cmd1-completion-trace'):
        event_state.handler_sp = event_state.frame - 0x70
        event_state.handler_memory = {'state': '01', 'claim': '01',
                          'zero_word': '00000000',
                          'zero_byte': '00'}
        for event_state.pair_index in range(5):
            event_state.expected_states.append(dict(
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                    + 0x0c + event_state.pair_index * 4,
                sp=event_state.handler_sp, spsr=0x200013c0,
                regs={0: 1, 8: 1, 9: 0, 10: 1},
                same_captured_regs=tuple(range(31)),
                saved_pairs=event_state.pair_index + 1,
                memory=dict(event_state.handler_memory)))
        event_state.expected_states.append(dict(
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x20,
            sp=event_state.handler_sp, spsr=0x200013c0,
            regs={0: 1, 8: 1, 9: 0, 10: 1,
                  29: event_state.handler_sp + 0x60},
            same_captured_regs=tuple(
                register for register in range(31)
                if register != 29),
            saved_pairs=5, memory=dict(event_state.handler_memory)))
    if event_state.handler_boundary in (
            'local-setup', 'validator-entry', 'validator-trace',
            'response-trace', 'cmd1-completion-trace'):
        event_state.moved = {}
        for event_state.offset, event_state.destination, event_state.source in (
                (0x24, 23, 5), (0x28, 24, 4),
                (0x2c, 22, 3), (0x30, 21, 2),
                (0x34, 20, 1), (0x38, 25, 0)):
            event_state.moved[event_state.destination] = event_state.source
            event_state.expected_states.append(dict(
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + event_state.offset,
                sp=event_state.handler_sp, spsr=0x200013c0,
                regs={29: event_state.handler_sp + 0x60},
                same_captured_regs=tuple(
                    register for register in range(31)
                    if register not in set(event_state.moved) | {29}),
                captured_reg_values=dict(event_state.moved), saved_pairs=5,
                memory=dict(event_state.handler_memory)))
        event_state.return_pc = run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x3c
        event_state.common_helper = dict(
            sp=event_state.handler_sp, spsr=0x200013c0,
            same_captured_regs=tuple(
                register for register in range(31)
                if register not in set(event_state.moved) | {29, 30}),
            captured_reg_values=dict(event_state.moved), saved_pairs=5,
            memory=dict(event_state.handler_memory))
        event_state.helper_states = (
            (run.FC_XNU_TXM_HANDLER_HELPER, 1),
            (run.FC_XNU_TXM_HANDLER_HELPER + 4, 1),
            (run.FC_XNU_TXM_HANDLER_HELPER + 8, event_state.handler_sp),
            (run.FC_XNU_TXM_HANDLER_HELPER + 0x0c, event_state.stack),
            (run.FC_XNU_TXM_HANDLER_HELPER + 0x10, event_state.stack + run.PAGE),
            (run.FC_XNU_TXM_HANDLER_HELPER + 0x14, event_state.frame),
            (event_state.return_pc, event_state.frame),
        )
        for event_state.helper_index, (event_state.helper_pc, event_state.x0_value) in enumerate(
                event_state.helper_states):
            event_state.state = dict(event_state.common_helper)
            event_state.state.update(pc=event_state.helper_pc,
                regs={0: event_state.x0_value, 29: event_state.handler_sp + 0x60,
                      30: event_state.return_pc})
            if event_state.helper_index >= 2:
                event_state.state['same_captured_regs'] = tuple(
                    register for register in
                        event_state.state['same_captured_regs'] if register != 0)
            event_state.expected_states.append(event_state.state)
        event_state.post_helper_preserved = tuple(
            register for register in
                event_state.common_helper['same_captured_regs']
            if register not in (0, 8))
        event_state.expected_states.append(dict(event_state.common_helper,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x40,
            regs={0: event_state.frame, 8: 1, 29: event_state.handler_sp + 0x60,
                  30: event_state.return_pc},
            same_captured_regs=event_state.post_helper_preserved))
        event_state.local_memory = dict(event_state.handler_memory)
        event_state.local_memory['local_marker'] = '0100000000000000'
        event_state.expected_states.append(dict(event_state.common_helper,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x44,
            regs={0: event_state.frame, 8: 1, 29: event_state.handler_sp + 0x60,
                  30: event_state.return_pc}, memory=event_state.local_memory,
            same_captured_regs=event_state.post_helper_preserved))
    if event_state.handler_boundary in (
            'validator-entry', 'validator-trace', 'response-trace',
            'cmd1-completion-trace'):
        event_state.global_page = run.FC_XNU_TXM_HANDLER_GLOBAL & ~(run.PAGE - 1)
        event_state.validator_preserved = tuple(register for register in
            event_state.post_helper_preserved if register != 26)
        event_state.validator_common = dict(
            sp=event_state.handler_sp, saved_pairs=5,
            captured_reg_values=dict(event_state.moved),
            memory=event_state.local_memory)
        event_state.expected_states.extend([
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x48,
                spsr=0x200013c0,
                regs={0: event_state.frame, 8: 1, 26: event_state.global_page,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.validator_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x4c,
                spsr=0x200013c0,
                regs={0: event_state.frame, 8: 1,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.validator_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x50,
                spsr=0x200013c0,
                regs={0: event_state.frame, 8: 0,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.validator_preserved),
        ])
        event_state.route_preserved = tuple(register for register in
            event_state.validator_preserved if register != 9)
        event_state.expected_states.extend([
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x54,
                spsr=0x200013c0,
                regs={0: event_state.frame, 8: 0,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.validator_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x58,
                spsr=0x200013c0,
                regs={0: event_state.frame, 8: 0, 9: event_state.handler_sp + 0x18,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.route_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x5c,
                spsr=0x800013c0,
                regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 0x18,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.route_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x74,
                spsr=0x800013c0,
                regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 0x18,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.route_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x78,
                spsr=0x800013c0,
                regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 0x18,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.route_preserved),
            dict(event_state.validator_common,
                pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x84,
                spsr=0x800013c0,
                regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 0x18,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
                same_captured_regs=event_state.route_preserved),
        ])
        event_state.after_x19 = tuple(register for register in
            event_state.route_preserved if register != 19)
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x88,
            spsr=0x800013c0,
            regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 0x18,
                  19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.after_x19))
        event_state.validator_memory = dict(event_state.local_memory,
            validator_base=run.struct.pack('<Q', event_state.stack).hex())
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x8c,
            spsr=0x800013c0,
            regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 0x18,
                  19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.after_x19,
            memory=event_state.validator_memory))
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x90,
            spsr=0x800013c0,
            regs={0: event_state.frame, 8: run.PAGE, 9: event_state.handler_sp + 0x18,
                  19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.after_x19,
            memory=event_state.validator_memory))
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x94,
            spsr=0x800013c0,
            regs={0: event_state.frame, 8: run.PAGE, 9: event_state.handler_sp + 0x18,
                  19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.after_x19,
            memory=event_state.validator_memory))
        event_state.validator_sizes = dict(event_state.validator_memory,
            validator_sizes=run.struct.pack('<QQ', run.PAGE, run.PAGE).hex())
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x98,
            spsr=0x800013c0,
            regs={0: event_state.frame, 8: run.PAGE, 9: event_state.handler_sp + 0x18,
                  19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.after_x19,
            memory=event_state.validator_sizes))
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x9c,
            spsr=0x800013c0,
            regs={0: event_state.handler_sp, 8: run.PAGE,
                  9: event_state.handler_sp + 0x18, 19: event_state.frame,
                  26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.after_x19,
            memory=event_state.validator_sizes))
        event_state.final_preserved = tuple(register for register in
            event_state.after_x19 if register != 1)
        event_state.expected_states.append(dict(event_state.validator_common,
            pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0xa0,
            spsr=0x800013c0,
            regs={0: event_state.handler_sp, 1: 0x2d, 8: run.PAGE,
                  9: event_state.handler_sp + 0x18, 19: event_state.frame,
                  26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                  29: event_state.handler_sp + 0x60, 30: event_state.return_pc},
            same_captured_regs=event_state.final_preserved,
            memory=event_state.validator_sizes))
        if event_state.handler_boundary in (
                'validator-trace', 'response-trace',
                'cmd1-completion-trace'):
            event_state.expected_states.append(dict(event_state.validator_common,
                pc=0xfffffe0017030b64,
                sp=event_state.handler_sp, spsr=0x800013c0,
                regs={0: event_state.handler_sp, 1: 0x2d, 8: run.PAGE,
                      9: event_state.handler_sp + 0x18, 19: event_state.frame,
                      26: run.FC_XNU_TXM_HANDLER_GLOBAL,
                      29: event_state.handler_sp + 0x60,
                      30: run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0xa4},
                same_captured_regs=event_state.final_preserved,
                captured_reg_values=dict(event_state.moved), saved_pairs=5,
                memory=event_state.validator_sizes,
                begin_validator_trace=True))
    if not event_state.prefix:
        event_state.expected_states = event_state.expected_states[:1]
    run.txm_context_step_state.update(active=True, index=0,
        expected_states=event_state.expected_states, report_key=event_state.report_key,
        roots=dict(event_state.roots),
        first_touch_va=run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 0x400 + 0x58,
        first_touch_pa=event_state.first_touch_pa,
        stack_page_pa=(event_state.stack_mapping['pa']
            if event_state.stack_mapping is not None else None),
        metadata_frame_pa=event_state.metadata_frame_pa,
        metadata_page_before=event_state.metadata_page_before,
        response_pointer_before=event_state.response_pointer_before,
        handler_boundary=event_state.handler_boundary,
        captured_regs={},
        metadata_offsets={'state': (0, 1), 'zero_word': (4, 4),
                          'claim': (0x58, 1),
                          'zero_byte': (0x79, 1),
                          'local_marker': (-0x58, 8),
                          'validator_base': (-0x70, 8),
                          'validator_sizes': (-0x68, 16)},
        event_kind=(('txm-handler-' + event_state.handler_boundary)
            if event_state.handler_boundary is not None
            else ('txm-context-outbound-branch-one-step' if event_state.outbound
            else ('txm-context-x18-branch-one-step' if event_state.x18_branch
            else ('txm-context-stack-metadata-init' if event_state.metadata
            else ('txm-context-stack-claim-one-step' if event_state.claim
            else ('txm-context-entry-register-prefix' if event_state.prefix
                  else 'txm-context-entry-one-step')))))),
        complete_reason=(('txm-handler-' + event_state.handler_boundary + '-complete')
            if event_state.handler_boundary is not None
            else ('txm-context-outbound-branch-one-step-complete'
            if event_state.outbound else ('txm-context-x18-branch-one-step-complete'
            if event_state.x18_branch else ('txm-context-stack-metadata-init-complete'
            if event_state.metadata else ('txm-context-stack-claim-one-step-complete'
            if event_state.claim else ('txm-context-entry-register-prefix-complete'
                           if event_state.prefix else 'txm-context-entry-one-step-complete')))))),
        mismatch_reason=(('txm-handler-' + event_state.handler_boundary + '-mismatch')
            if event_state.handler_boundary is not None
            else ('txm-context-outbound-branch-one-step-mismatch'
            if event_state.outbound else ('txm-context-x18-branch-one-step-mismatch'
            if event_state.x18_branch else ('txm-context-stack-metadata-init-mismatch'
            if event_state.metadata else ('txm-context-stack-claim-one-step-mismatch'
            if event_state.claim else ('txm-context-entry-register-prefix-mismatch'
                           if event_state.prefix else 'txm-context-entry-one-step-mismatch')))))))
    event_state.ctx.elr = event_state.elr_gl1
    event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.spsr_gl1)
    event_state.ctx.spsr.SS = 1
    run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
    run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
    run.report.pop('stop_reason', None)
    event_state.ret = run.EXC_RET.HANDLED
