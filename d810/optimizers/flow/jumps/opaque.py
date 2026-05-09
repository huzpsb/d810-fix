from ida_hexrays import *

from d810.ast import AstLeaf, AstConstant, AstNode
from d810.optimizers.flow.jumps.handler import JumpOptimizationRule


class JnzRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_neg,
                           AstNode(m_and,
                                   AstNode(m_bnot,
                                           AstLeaf("x_0")),
                                   AstConstant("1", 1)))
    RIGHT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule2(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_or,
                           AstNode(m_bnot,
                                   AstLeaf("x_0")),
                           AstConstant("1", 1))
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule3(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_xor,
                           AstNode(m_xor,
                                   AstLeaf("x_0"),
                                   AstConstant("c_1")),
                           AstNode(m_and,
                                   AstLeaf("x_0"),
                                   AstConstant("c_2")))
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        tmp = left_candidate["c_1"].value & left_candidate["c_2"].value
        if tmp == 0:
            return False
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule4(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_sub,
                           AstConstant("3", 3),
                           AstLeaf("x_0"))
    RIGHT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule5(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_xor,
                           AstNode(m_sub,
                                   AstConstant("3", 3),
                                   AstLeaf("x_0")),
                           AstLeaf("x_0"))
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule6(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_xor,
                           AstNode(m_bnot,
                                   AstNode(m_sub,
                                           AstConstant("3", 3),
                                           AstLeaf("x_0"))),
                           AstNode(m_bnot,
                                   AstLeaf("x_0")))
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule7(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    LEFT_PATTERN = AstNode(m_and,
                           AstLeaf("x_0"),
                           AstConstant("c_1"))
    RIGHT_PATTERN = AstConstant("c_2")
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        tmp = left_candidate["c_1"].value & right_candidate["c_2"].value
        if tmp == right_candidate["c_2"].value:
            return False
        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule8(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jnz, m_jz]
    PATTERN = AstNode(m_or,
                      AstLeaf("x_0"),
                      AstConstant("c_1"))
    RIGHT_PATTERN = AstConstant("c_2")
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        tmp = left_candidate["c_1"].value & right_candidate["c_2"].value
        if tmp == left_candidate["c_1"].value:
            return False

        if opcode == m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JbRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jb]
    PATTERN = AstNode(m_xdu,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("1", 1)))
    RIGHT_PATTERN = AstConstant("2", 2)
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class JaeRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jae]
    PATTERN = AstNode(m_and,
                      AstLeaf("x_0"),
                      AstConstant("c_1"))
    RIGHT_PATTERN = AstConstant("c_2")
    REPLACEMENT_OPCODE = m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if left_candidate["c_1"].value >= right_candidate["c_2"].value:
            return False
        self.jump_replacement_block_serial = self.direct_block_serial
        return True

import ida_hexrays
from d810.optimizers.flow.jumps.handler import JumpOptimizationRule

class V9_UnsafeOpaquePointerAliasRule(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = None
    RIGHT_PATTERN = None
    def check_pattern_and_replace(self, blk, instruction, left_ast, right_ast):
        if instruction.opcode not in self.ORIGINAL_JUMP_OPCODES:
            return None
        back_edge_idx = -1
        for i in range(2):
            if blk.succ(i) <= blk.serial:
                back_edge_idx = i
                break
        if back_edge_idx == -1:
            return None
        stx_ins = None
        curr = instruction.prev
        while curr:
            if curr.opcode in [ida_hexrays.m_stx, ida_hexrays.m_mov]:
                stx_ins = curr
                break
            curr = curr.prev
        if not stx_ins:
            return None
        source_mop = stx_ins.l
        is_source_constant = (source_mop.t == ida_hexrays.mop_n)
        if not is_source_constant:
            return None
        real_next_block = blk.succ(1 - back_edge_idx)
        new_ins = ida_hexrays.minsn_t(instruction)
        new_ins.opcode = ida_hexrays.m_goto
        new_ins.l.make_blkref(real_next_block)
        new_ins.r.erase()
        new_ins.d.make_blkref(real_next_block)
        return new_ins