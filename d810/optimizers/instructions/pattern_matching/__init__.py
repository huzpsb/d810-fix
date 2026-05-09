from d810.utils import get_all_subclasses
from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule, PatternOptimizer
from d810.optimizers.instructions.pattern_matching.rewrite_add import *
from d810.optimizers.instructions.pattern_matching.rewrite_and import *
from d810.optimizers.instructions.pattern_matching.rewrite_bnot import *
from d810.optimizers.instructions.pattern_matching.rewrite_cst import *
from d810.optimizers.instructions.pattern_matching.rewrite_mov import *
from d810.optimizers.instructions.pattern_matching.rewrite_mul import *
from d810.optimizers.instructions.pattern_matching.rewrite_neg import *
from d810.optimizers.instructions.pattern_matching.rewrite_predicates import *
from d810.optimizers.instructions.pattern_matching.rewrite_or import *
from d810.optimizers.instructions.pattern_matching.rewrite_sub import *
from d810.optimizers.instructions.pattern_matching.rewrite_xor import *
from d810.optimizers.instructions.pattern_matching.weird import *
from d810.optimizers.instructions.pattern_matching.experimental import *

# v9 rules
import ida_bytes
import idc

from ida_hexrays import m_sub, m_mul, m_umod, mop_d
from d810.ast import AstNode, AstLeaf, AstConstant
from d810.hexrays_helpers import equal_mops_bypass_xdu

def is_mop_inside(mop, target_mop):
    if not mop:
        return False
    if equal_mops_bypass_xdu(mop, target_mop):
        return True
    if mop.t == mop_d:
        ins = mop.d
        return (is_mop_inside(ins.l, target_mop) or
                is_mop_inside(ins.r, target_mop) or
                is_mop_inside(ins.d, target_mop))
    return False

class V9_UnsafeMagicModulo(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf("x"),
                      AstNode(m_mul, AstLeaf("div_part"), AstConstant("divisor")))
    REPLACEMENT_PATTERN = AstNode(m_umod, AstLeaf("x"), AstConstant("divisor"))
    def check_candidate(self, candidate):
        target_x = candidate["x"].mop
        div_mop = candidate["div_part"].mop
        return is_mop_inside(div_mop, target_x)

class V9_IndirectCall(PatternMatchingRule):
    PATTERN = AstNode(m_add, AstLeaf("obj_ptr"), AstConstant("key"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("new_target"))

    def check_candidate(self, candidate):
        m = candidate["obj_ptr"].mop
        if m.t != mop_v:
            return False
        addr = m.g
        val = ida_bytes.get_qword(addr)
        if val == 0:
            return False
        key = candidate["key"].value
        size = candidate.size
        # The true address
        real_target = (val + key) & 0xFFFFFFFFFFFFFFFF
        if 0x180001000 <= real_target <= 0x181824000:
            candidate.add_constant_leaf("new_target", real_target, size)
            return True
        return False

# Fold globals cleanly for each operation type
class V9_FoldGlobal_Mov(PatternMatchingRule):
    PATTERN = AstNode(m_mov, AstLeaf("x"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("c_val"))
    def check_candidate(self, candidate):
        m = candidate["x"].mop
        if m.t != mop_v: return False
        addr = m.g
        if m.size == 4: v = ida_bytes.get_dword(addr)
        elif m.size == 8: v = ida_bytes.get_qword(addr)
        else: return False
        if v == 0: return False
        candidate.add_constant_leaf("c_val", v, m.size)
        return True

class V9_FoldGlobal_Mul(PatternMatchingRule):
    PATTERN = AstNode(m_mul, AstLeaf("x"), AstLeaf("other"))
    REPLACEMENT_PATTERN = AstNode(m_mul, AstConstant("c_val"), AstLeaf("other"))
    def check_candidate(self, candidate):
        m = candidate["x"].mop
        if m.t != mop_v: return False
        addr = m.g
        if m.size == 4: v = ida_bytes.get_dword(addr)
        elif m.size == 8: v = ida_bytes.get_qword(addr)
        else: return False
        if v == 0: return False
        candidate.add_constant_leaf("c_val", v, m.size)
        return True

class V9_FoldGlobal_Add(PatternMatchingRule):
    PATTERN = AstNode(m_add, AstLeaf("x"), AstLeaf("other"))
    REPLACEMENT_PATTERN = AstNode(m_add, AstConstant("c_val"), AstLeaf("other"))
    def check_candidate(self, candidate):
        m = candidate["x"].mop
        if m.t != mop_v: return False
        addr = m.g
        if m.size == 4: v = ida_bytes.get_dword(addr)
        elif m.size == 8: v = ida_bytes.get_qword(addr)
        else: return False
        if v == 0: return False
        candidate.add_constant_leaf("c_val", v, m.size)
        return True

class V9_FoldGlobal_Sub(PatternMatchingRule):
    PATTERN = AstNode(m_sub, AstLeaf("x"), AstLeaf("other"))
    REPLACEMENT_PATTERN = AstNode(m_sub, AstConstant("c_val"), AstLeaf("other"))
    def check_candidate(self, candidate):
        m = candidate["x"].mop
        if m.t != mop_v: return False
        addr = m.g
        if m.size == 4: v = ida_bytes.get_dword(addr)
        elif m.size == 8: v = ida_bytes.get_qword(addr)
        else: return False
        if v == 0: return False
        candidate.add_constant_leaf("c_val", v, m.size)
        return True

class V9_FoldGlobal_Xor(PatternMatchingRule):
    PATTERN = AstNode(m_xor, AstLeaf("x"), AstLeaf("other"))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstConstant("c_val"), AstLeaf("other"))
    def check_candidate(self, candidate):
        m = candidate["x"].mop
        if m.t != mop_v: return False
        addr = m.g
        if m.size == 4: v = ida_bytes.get_dword(addr)
        elif m.size == 8: v = ida_bytes.get_qword(addr)
        else: return False
        if v == 0: return False
        candidate.add_constant_leaf("c_val", v, m.size)
        return True

PATTERN_MATCHING_RULES = [x() for x in get_all_subclasses(PatternMatchingRule)]

print(f"Loaded {len(PATTERN_MATCHING_RULES)} pattern matching rules.")
found_v9 = any(isinstance(rule, V9_IndirectCall) for rule in PATTERN_MATCHING_RULES)
if not found_v9:
    print("Warning: V9_IndirectCall rule not found. This might indicate an issue with rule loading.")