# .eh_frame/.gcc_exception_table parser/formatter for IDA
# Copyright (c) 2012 Igor Skochinsky
# Version 0.1 2012-06-19
#
# This software is provided 'as-is', without any express or implied
# warranty. In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
#    1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
#    2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
#
#    3. This notice may not be removed or altered from any source
#    distribution.

OPTION_PARSE_CFA = True

IS64 = idaapi.getseg(here()).bitness == 2

PTRSIZE = [4, 8][IS64]

def ptrval(ea):
  if IS64:
    return get_qword(ea)
  else:
    return get_wide_dword(ea)   

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m

def ForceWord(ea):
  if ea != BADADDR and ea != 0:
    if not is_word(get_full_flags(ea)) or get_item_end(ea) != 2:
      del_items(ea, 2, DELIT_SIMPLE)
      create_word(ea)
    if is_off0(get_full_flags(ea)) and GetFixupTgtType(ea) == -1:
      # remove the offset
      OpHex(ea, 0)
    
def ForceDword(ea):
  if ea != BADADDR and ea != 0:
    if not is_dword(get_full_flags(ea)) or get_item_end(ea) != 4:
      del_items(ea, 4, DELIT_SIMPLE)
      create_dword(ea)
    if is_off0(get_full_flags(ea)) and GetFixupTgtType(ea) == -1:
      # remove the offset
      OpHex(ea, 0)
    
def ForceQword(ea):
  if ea != BADADDR and ea != 0:
    if not is_qword(get_full_flags(ea)) or get_item_end(ea) != 8:
      del_items(ea, 8, DELIT_SIMPLE)
      create_qword(ea)
    if is_off0(get_full_flags(ea)) and GetFixupTgtType(ea) == -1:
      # remove the offset
      OpHex(ea, 0)

def ForcePtr(ea, delta = 0):
  if IS64:
    ForceQword(ea)
  else:
    ForceDword(ea)
  if GetFixupTgtType(ea) != -1 and is_off0(get_full_flags(ea)):
    # don't touch fixups
    return
  pv = ptrval(ea)
  if pv != 0 and pv != BADADDR:
    # apply offset again
    if idaapi.is_spec_ea(pv):
      delta = 0
    OpOffEx(ea, 0, [REF_OFF32, REF_OFF64][IS64], -1, 0, delta)

def format_byte(ea, cmt = None):
  if ea != BADADDR and ea != 0:
    if not is_byte(get_full_flags(ea)) or get_item_end(ea) != 1:
      del_items(ea, 1, DELIT_SIMPLE)
      create_byte(ea)
  if cmt:
    set_cmt(ea, cmt, False)
  return get_original_byte(ea)

def format_dword(ea, cmt = None):
  ForceDword(ea)
  if cmt:
    set_cmt(ea, cmt, False)
  return get_wide_dword(ea), ea + 4

def format_string(ea, cmt = None):
  s = get_strlit_contents(ea, -1, STRTYPE_C)
  slen = len(s)+1
  #print "slen = %d" % (slen)
  del_items(ea, slen, DELIT_SIMPLE)
  create_strlit(ea, ea + slen)
  if cmt:
    set_cmt(ea, cmt, False)
  return s, ea + slen
  
def format_leb128(ea, cmt = None, signed = False):
  val, ea2 = read_enc_val(ea, [DW_EH_PE_uleb128, DW_EH_PE_uleb128][signed], True)
  if cmt:
    set_cmt(ea, cmt, False)
  return val, ea2

def read_leb128(ea, signed):
  v = 0
  s = 0
  while True:
    b = get_original_byte(ea)
    v |= (b&0x7F)<<s
    s += 7
    ea += 1
    if (b & 0x80) == 0:
      break
    if s > 64:
      print "Bad leb128 at %08X" % (ea - s/7)
      return BADADDR
  if signed and (b & 0x40):
    v -= (1<<s)
  return v, ea

def read_uleb128(ea):
  return read_leb128(ea, False)

def read_sleb128(ea):
  return read_leb128(ea, True)

val_format = {
  0x00: "DW_EH_PE_ptr", 
  0x01: "DW_EH_PE_uleb128", 
  0x02: "DW_EH_PE_udata2", 
  0x03: "DW_EH_PE_udata4", 
  0x04: "DW_EH_PE_udata8", 
  0x08: "DW_EH_PE_signed", 
  0x09: "DW_EH_PE_sleb128", 
  0x0A: "DW_EH_PE_sdata2", 
  0x0B: "DW_EH_PE_sdata4", 
  0x0C: "DW_EH_PE_sdata8",
}
val_appl = {
  0x00: "DW_EH_PE_absptr", 
  0x10: "DW_EH_PE_pcrel", 
  0x20: "DW_EH_PE_textrel", 
  0x30: "DW_EH_PE_datarel", 
  0x40: "DW_EH_PE_funcrel", 
  0x50: "DW_EH_PE_aligned", 
}

# Encoding Types
DW_EH_PE_ptr       = 0x00
DW_EH_PE_uleb128   = 0x01
DW_EH_PE_udata2    = 0x02
DW_EH_PE_udata4    = 0x03
DW_EH_PE_udata8    = 0x04
DW_EH_PE_signed    = 0x08
DW_EH_PE_sleb128   = 0x09
DW_EH_PE_sdata2    = 0x0A
DW_EH_PE_sdata4    = 0x0B
DW_EH_PE_sdata8    = 0x0C
DW_EH_PE_absptr    = 0x00
DW_EH_PE_pcrel     = 0x10
DW_EH_PE_textrel   = 0x20
DW_EH_PE_datarel   = 0x30
DW_EH_PE_funcrel   = 0x40
DW_EH_PE_aligned   = 0x50
DW_EH_PE_indirect  = 0x80
DW_EH_PE_omit      = 0xFF
DW_EH_PE_indirect  = 0x80 
DW_EH_PE_omit      = 0xFF

DW_CFA_advance_loc = 0x40
DW_CFA_offset = 0x80
DW_CFA_restore = 0xC0
DW_CFA_nop = 0x00
DW_CFA_set_loc = 0x01
DW_CFA_advance_loc1 = 0x02
DW_CFA_advance_loc2 = 0x03
DW_CFA_advance_loc4 = 0x04
DW_CFA_offset_extended = 0x05
DW_CFA_restore_extended = 0x06
DW_CFA_undefined = 0x07
DW_CFA_same_value = 0x08
DW_CFA_register = 0x09
DW_CFA_remember_state = 0x0A
DW_CFA_restore_state = 0x0B
DW_CFA_def_cfa = 0x0C
DW_CFA_def_cfa_register = 0x0D
DW_CFA_def_cfa_offset = 0x0E
DW_CFA_def_cfa_expression = 0x0F
DW_CFA_expression = 0x10
DW_CFA_offset_extended_sf = 0x11
DW_CFA_def_cfa_sf = 0x12
DW_CFA_def_cfa_offset_sf = 0x13
DW_CFA_val_offset = 0x14
DW_CFA_val_offset_sf = 0x15
DW_CFA_val_expression = 0x16
DW_CFA_lo_user = 0x1C
DW_CFA_hi_user = 0x3F
DW_CFA_MIPS_advance_loc8 = 0x1D
DW_CFA_GNU_window_save = 0x2D
DW_CFA_AARCH64_negate_ra_state = 0x2D
DW_CFA_GNU_args_size = 0x2E
DW_CFA_GNU_negative_offset_extended = 0x2F

cfa_names = {
  0x40: "DW_CFA_advance_loc",
  0x80: "DW_CFA_offset",
  0xC0: "DW_CFA_restore",
  0x00: "DW_CFA_nop",
  0x01: "DW_CFA_set_loc",
  0x02: "DW_CFA_advance_loc1",
  0x03: "DW_CFA_advance_loc2",
  0x04: "DW_CFA_advance_loc4",
  0x05: "DW_CFA_offset_extended",
  0x06: "DW_CFA_restore_extended",
  0x07: "DW_CFA_undefined",
  0x08: "DW_CFA_same_value",
  0x09: "DW_CFA_register",
  0x0A: "DW_CFA_remember_state",
  0x0B: "DW_CFA_restore_state",
  0x0C: "DW_CFA_def_cfa",
  0x0D: "DW_CFA_def_cfa_register",
  0x0E: "DW_CFA_def_cfa_offset",
  0x0F: "DW_CFA_def_cfa_expression",
  0x10: "DW_CFA_expression",
  0x11: "DW_CFA_offset_extended_sf",
  0x12: "DW_CFA_def_cfa_sf",
  0x13: "DW_CFA_def_cfa_offset_sf",
  0x14: "DW_CFA_val_offset",
  0x15: "DW_CFA_val_offset_sf",
  0x16: "DW_CFA_val_expression",
  0x1C: "DW_CFA_lo_user",
  0x3F: "DW_CFA_hi_user",
  0x1D: "DW_CFA_MIPS_advance_loc8",
  0x2D: "DW_CFA_GNU_window_save",
  0x2D: "DW_CFA_AARCH64_negate_ra_state",
  0x2E: "DW_CFA_GNU_args_size",
  0x2F: "DW_CFA_GNU_negative_offset_extended"
}

DWARF_CFA_OPCODE_MASK = 0xC0
DWARF_CFA_OPERAND_MASK = 0x3F

def format_cfa_op(ea, cmt):
  full_op = format_byte(ea)

  op = full_op & DWARF_CFA_OPCODE_MASK
  operand = full_op & DWARF_CFA_OPERAND_MASK

  if op == DW_CFA_advance_loc or op == DW_CFA_offset or op == DW_CFA_restore:
    if op in cfa_names:
      addcmt = "Opcode %s (%d), Operand: %d" % (cfa_names[op], op, operand)
    else:
      addcmt = "Bad Encoding: %02X" % op
  else:
    if full_op in cfa_names:
      addcmt = "Opcode %s (%d)" % (cfa_names[full_op], full_op)
    else:
      addcmt = "Bad Encoding: %02X" % full_op

  set_cmt(ea, "%s: %s" % (cmt, addcmt), False)
  return full_op, op, ea + 1

def format_advance_arg(ea, codeAlignFactor, argSize, cmt):
  value = 0

  if argSize == 1:
    if not is_byte(get_full_flags(ea)) or get_item_end(ea) != 1:
      del_items(ea, 1, DELIT_SIMPLE)
      create_byte(ea)
      value = get_original_byte(ea)
  elif argSize == 2:
    ForceWord(ea)
    value = get_wide_word(ea)
  elif argSize == 4:
    ForceDword(ea)
    value = get_wide_dword(ea)

  value *= codeAlignFactor

  addcmt = "%d" % value

  set_cmt(ea, "%s: %s" % (cmt, addcmt), False)
  return value, ea + argSize

def format_byte(ea, cmt = None):
  if ea != BADADDR and ea != 0:
    if not is_byte(get_full_flags(ea)) or get_item_end(ea) != 1:
      del_items(ea, 1, DELIT_SIMPLE)
      create_byte(ea)
  if cmt:
    set_cmt(ea, cmt, False)
  return get_original_byte(ea)

def format_enc(ea, cmt):
  v = format_byte(ea)
  if v == DW_EH_PE_omit:
    addcmt = "DW_EH_PE_omit"
  else:
    f, a = v&0x0F, v&0x70
    if f in val_format and a in val_appl:
      addcmt = "%s|%s" % (val_format[f], val_appl[a])
      if v & DW_EH_PE_indirect:
        addcmt += "|DW_EH_PE_indirect"
    else:
      addcmt = "Bad encoding: %02X" % v
  set_cmt(ea, "%s: %s" % (cmt, addcmt), False)
  return v, ea + 1

def enc_size(enc):
  f = enc & 0x0F
  if f == DW_EH_PE_ptr:
    return PTRSIZE
  elif f in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    return 2
  elif f in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    return 4
  elif f in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    return 8
  elif f != DW_EH_PE_omit:
    Warning("logic error: encoding %02X is not fixed size" % (enc))
  return 0

def read_enc_val(ea, enc, format = False):
  if enc == DW_EH_PE_omit:
    Warning("%08X: logic error in read_enc_val" % ea)
    return BADADDR, BADADDR
  start = ea
  f, a = enc&0x0F, enc&0x70
  if f == DW_EH_PE_ptr:
    val = ptrval(ea)
    ea += PTRSIZE
    if format:
      ForcePtr(start)
  elif f in [DW_EH_PE_uleb128, DW_EH_PE_sleb128]:
    val, ea = read_leb128(ea, f== DW_EH_PE_sleb128)
    format_byte(start)
    if ea - start > 1:
      make_array(start, ea - start)
  elif f in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    val = get_wide_word(ea)
    ea += 2
    if f == DW_EH_PE_sdata2:
      val = SIGNEXT(val, 16)
    if format:
      ForceWord(start)
  elif f in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    val = get_wide_dword(ea)
    ea += 4
    if f == DW_EH_PE_sdata4:
      val = SIGNEXT(val, 32)
    if format:
      ForceDword(start)
  elif f in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    val = get_qword(ea)
    ea += 8
    if f == DW_EH_PE_sdata8:
      val = SIGNEXT(val, 64)
    if format:
      ForceQword(start)
  else:
    print "%08X: don't know how to handle encoding %02X" % (start, enc)
    return BADADDR, BADADDR
  if a == DW_EH_PE_pcrel:   
    if val != 0:
      make_reloff(start, start)
      val += start
      val &= (1<<(PTRSIZE*8)) - 1
      # OpOffEx(start, 0, REF_OFF32, BADADDR, start, 0)
  elif a != DW_EH_PE_absptr:
    print "%08X: don't know how to handle encoding %02X" % (start, enc)
    return BADADDR, BADADDR
  if (enc & DW_EH_PE_indirect) and val != 0:
    if not is_loaded(val):
      print "%08X: trying to dereference invalid pointer %08X" % (start, val)
      return BADADDR, BADADDR
    val = ptrval(val)
  return val, ea

def make_reloff(ea, base, subtract = False):
  f = get_full_flags(ea)
  if is_byte(f) and get_item_end(ea) == 1 or \
     is_word(f) and get_item_end(ea) == 2 or \
     is_dword(f) and get_item_end(ea) == 4 or \
     is_qword(f) and get_item_end(ea) == 8:
    ri = idaapi.refinfo_t()
    flag = REF_OFF32|REFINFO_NOBASE
    if subtract:
      flag |= idaapi.REFINFO_SUBTRACT
    ri.init(flag, base)
    idaapi.op_offset_ex(ea, 0, ri)

def format_cfa(ea, codeAlignFactor, dataAlignFactor, pointerEncoding, instLength):
  if OPTION_PARSE_CFA == False:
    format_byte(ea, "Initial CFE Instructions")
    make_array(ea, instr_length)
    return

  end_ea = ea + instLength
  instNumber = 0
  while ea < end_ea:
    full_op, small_op, ea = format_cfa_op(ea, "CFA")

    if full_op == DW_CFA_advance_loc2:
      value, ea = format_advance_arg(ea, codeAlignFactor, 2, "Arg1")
    elif full_op == DW_CFA_advance_loc4:
      value, ea = format_advance_arg(ea, codeAlignFactor, 4, "Arg1")
    elif full_op == DW_CFA_offset_extended:
      regnum, ea = format_leb128(ea, "regnum", False)
      value, ea = format_leb128(ea, "offset", False) # TODO: DataAlignFactor
    elif full_op == DW_CFA_offset_extended_sf:
      regnum, ea = format_leb128(ea, "regnum", False)
      value, ea = format_leb128(ea, "offset", True) # TODO: DataAlignFactor
    elif full_op == DW_CFA_restore_extended:
      regnum, ea = format_leb128(ea, "regnum", False)
    elif full_op == DW_CFA_set_loc:
      sa = ea
      enc, ea = read_enc_val(ea, pointerEncoding, False)
      set_cmt(ea, "location: 0x%08X" % enc, False)
    elif full_op == DW_CFA_undefined:
      regnum, ea = format_leb128(ea, "regnum", False)
    elif full_op == DW_CFA_same_value:
      regnum, ea = format_leb128(ea, "regnum", False)
    elif full_op == DW_CFA_register:
      regnum, ea = format_leb128(ea, "regnum", False)
    elif full_op == DW_CFA_def_cfa:
      regnum, ea = format_leb128(ea, "regnum", False)
      val, ea = format_leb128(ea, "value", False)  # TODO: DataAlignFactor
    elif full_op == DW_CFA_def_cfa_sf:
      regnum, ea = format_leb128(ea, "regnum", False)
      val, ea = format_leb128(ea, "value", True)  # TODO: DataAlignFactor
    elif full_op == DW_CFA_def_cfa_register:
      regnum, ea = format_leb128(ea, "regnum", False)
    elif full_op == DW_CFA_def_cfa_offset:
      regnum, ea = format_leb128(ea, "value", False)  # TODO: DataAlignFactor
    elif full_op == DW_CFA_def_cfa_offset_sf:
      regnum, ea = format_leb128(ea, "value", True)  # TODO: DataAlignFactor
    elif full_op == DW_CFA_def_cfa_expression:
      exprLength, ea = format_leb128(ea, "len", False)
      format_byte(ea, "Expression")
      make_array(ea, exprLength)
    elif full_op == DW_CFA_expression:
      regnum, ea = format_leb128(ea, "regnum", False)
      exprLength, ea = format_leb128(ea, "len", False)
      format_byte(ea, "Expression")
      make_array(ea, exprLength)
    elif full_op == DW_CFA_val_expression:
      regnum, ea = format_leb128(ea, "regnum", False)
      exprLength, ea = format_leb128(ea, "len", False)
      format_byte(ea, "Expression")
      make_array(ea, exprLength)
    elif full_op == DW_CFA_GNU_args_size:
      val, ea = format_leb128(ea, "value", False)
    elif full_op == DW_CFA_GNU_negative_offset_extended:
      regnum, ea = format_leb128(ea, "regnum", False)
      val, ea = format_leb128(ea, "value", False)  # TODO: ~(val * DataAlignFactor) + 1
    elif full_op == DW_CFA_val_offset:
      regnum, ea = format_leb128(ea, "regnum", False)
      val, ea = format_leb128(ea, "value", False)  # TODO: DataAlignFactor
    elif full_op == DW_CFA_val_offset_sf:
      regnum, ea = format_leb128(ea, "regnum", False)
      val, ea = format_leb128(ea, "value", True)  # TODO: DataAlignFactor

    # Small ops only down here
    elif small_op == DW_CFA_advance_loc1:
      value, ea = format_advance_arg(ea, codeAlignFactor, 1, "Arg1")
    elif small_op == DW_CFA_offset:
      value, ea = format_leb128(ea, "offset", False) # TODO: DataAlignFactor

def format_lsda(ea, lpstart = None, sjlj = False):
  lpstart_enc, ea = format_enc(ea, "LPStart encoding")
  if lpstart_enc != DW_EH_PE_omit:
    lpstart, ea2 = read_enc_val(ea, lpstart_enc, True)
    set_cmt(ea, "LPStart: %08X" % val, False)
    ea = ea2
  ttype_enc, ea = format_enc(ea, "TType encoding")
  ttype_addr = BADADDR
  if ttype_enc != DW_EH_PE_omit:
    ttype_off, ea2 = read_enc_val(ea, DW_EH_PE_uleb128, True)
    ttype_addr = ea2 + ttype_off
    set_cmt(ea, "TType offset: %08X -> %08X" % (ttype_off, ttype_addr), False)
    make_reloff(ea, ea2)
    ea = ea2
  cs_enc, ea = format_enc(ea, "call site encoding")
  cs_len, ea2 = read_enc_val(ea, DW_EH_PE_uleb128, True)
  action_tbl = ea2 + cs_len
  set_cmt(ea, "call site table length: %08X\naction table start: %08X" % (cs_len, action_tbl), False)
  make_reloff(ea, ea2)
  ea = ea2
  i = 0
  actions = []
  while ea < action_tbl:
    if sjlj:
      cs_lp, ea2 = read_enc_val(ea, DW_EH_PE_uleb128, True)
      cs_action, ea3 = read_enc_val(ea2, DW_EH_PE_uleb128, True)
      set_cmt(ea, "cs_lp[%d] = %d" % (i, cs_lp), False)
      act_ea = ea2
      ea = ea3
    else:
      cs_start, ea2 = read_enc_val(ea, cs_enc, True)
      cs_len,   ea3 = read_enc_val(ea2, cs_enc & 0x0F, True)
      cs_lp,    ea4 = read_enc_val(ea3, cs_enc, True)
      cs_action,ea5 = read_enc_val(ea4, DW_EH_PE_uleb128, True)
      if lpstart != None:
        cs_start += lpstart
        if cs_lp != 0:
          cs_lp    += lpstart
          set_cmt(ea3, "cs_lp[%d] = %08X" % (i, cs_lp), False)
          set_cmt(cs_lp, "Landing pad for %08X..%08X" % (cs_start, cs_start + cs_len), False)
        else:
          set_cmt(ea3, "cs_lp[%d] = 0 (none)" % (i), False)
      set_cmt(ea, "cs_start[%d] = %08X" % (i, cs_start), False)
      set_cmt(ea2, "cs_len[%d] = %d (end = %08X)" % (i, cs_len, cs_start + cs_len), False)
      if lpstart != None:
        make_reloff(ea, lpstart)
        if cs_lp != 0:
          make_reloff(ea3, lpstart)
      act_ea = ea4
      ea = ea5
    if cs_action == 0:
      addcmt = "no action"
    else:
      addcmt = "%08X" % (action_tbl + cs_action - 1)
      actions.append(cs_action)
    set_cmt(act_ea, "cs_action[%d] = %d (%s)" % (i, cs_action, addcmt), False)
    i += 1
  
  actions2 = []
  while len(actions):
    act = actions.pop()
    if not act in actions2:
      act_ea = action_tbl + act - 1
      # print "action %d -> %08X" % (act, act_ea)
      actions2.append(act)
      ar_filter,ea2 = read_enc_val(act_ea, DW_EH_PE_sleb128, True)
      ar_disp,  ea3 = read_enc_val(ea2, DW_EH_PE_sleb128, True)
      if ar_filter == 0:
        addcmt = "cleanup"
      else:
        if ttype_addr == BADADDR:
          addcmt = "no type table?!"
        else:
          if ar_filter > 0:
            # catch expression
            type_slot = ttype_addr - ar_filter * enc_size(ttype_enc)
            set_cmt(type_slot, "Type index %d" % ar_filter, False)
            type_ea, eatmp = read_enc_val(type_slot, ttype_enc, True)
            addcmt = "catch type typeinfo = %08X" % (type_ea)
          else:
            # exception spec list
            type_slot = ttype_addr - ar_filter - 1
            addcmt = "exception spec index list = %08X" % (type_slot)
          
      set_cmt(act_ea, "ar_filter[%d]: %d (%s)" % (act, ar_filter, addcmt), False)
      if ar_disp == 0:
        addcmt = "end"
      else:
        next_ea = ea2 + ar_disp
        next_act = next_ea - act_ea + act
        addcmt = "next: %d => %08X" % (next_act, next_ea)
        actions.append(next_act)
      set_cmt(ea2, "ar_disp[%d]: %d (%s)" % (act, ar_disp, addcmt), False)

class AugParams:
  def __init__(self):
    self.aug_present = False
    self.lsda_encoding = DW_EH_PE_omit
    self.personality_ptr = None
    self.fde_encoding = DW_EH_PE_absptr
    
aug_params = {}

def format_cie_fde(ea):
  start = ea
  sz, ea = format_dword(ea, "Size")
  if sz == 0:
    print "%08X: end of CIEs" % start
    return BADADDR
  else:
    make_reloff(start, ea)
  end_ea = ea + sz
  cie_id, ea = format_dword(ea, "CIE id")
  is_cie = cie_id == 0
  print "%08X: %s, size=%d" % (start, ["FIE", "CDE"][is_cie], sz)
  if is_cie:
    aug = AugParams()

    ver, ea = format_byte(ea, "Version"), ea+1
    augmentation, ea = format_string(ea, "Augmentation String")
    aug.code_align, ea = format_leb128(ea, "Code alignment factor")
    aug.data_align, ea = format_leb128(ea, "Data alignment factor", True)
    if ver == 1:
      retreg, ea = format_byte(ea, "Return register"), ea+1
    else:
      retreg, ea = format_leb128(ea, "Return register")

    if augmentation[0:1]=='z':
      augm_len, ea = format_leb128(ea, "Augmentation data length")
      aug.aug_present = True
      for c in augmentation[1:]:
        if c == 'L':
          aug.lsda_encoding, ea = format_enc(ea, "L: LSDA pointer encoding")
        elif c == 'P':                    
          enc, ea = format_enc(ea, "P: Personality routine encoding")
          aug.personality_ptr, ea2 = read_enc_val(ea, enc, True)
          set_cmt(ea, "P: Personality routine pointer: %08X" % aug.personality_ptr, False)
          ea = ea2
        elif c == 'R':
          aug.fde_encoding, ea = format_enc(ea, "R: FDE pointers encoding")
        else:
          print "%08X: unhandled augmentation string char: %c" % (ea, c)
          return BADADDR 
    
    instr_length = end_ea - ea
    if instr_length > 0:
      format_cfa(ea, aug.code_align, aug.data_align, aug.fde_encoding, instr_length)
      ea = end_ea # just skip to the end lol
    else:
      print "%08X: insn_len = %d?!" % (ea, instr_length)
    aug_params[start] = aug
    # print "instr_length:", instr_length
  else:
    cie_ea = ea-4-cie_id
    if cie_ea in aug_params:
      aug = aug_params[cie_ea]
    else:
      print "%08X: CIE %08X not present?!" % (ea-4, cie_ea)
      return BADADDR
    make_reloff(ea-4, ea-4, True)
    set_cmt(ea-4, "CIE pointer", False)
    init_loc, ea2 = read_enc_val(ea, aug.fde_encoding, True)
    set_cmt(ea, "Initial location=%08X" % init_loc, False)
    ea = ea2
    range_len, ea2 = read_enc_val(ea, aug.fde_encoding & 0x0F, True)
    set_cmt(ea, "Range length=%08X (end=%08X)" % (range_len, range_len + init_loc), False)
    if range_len:
      make_reloff(ea, init_loc)
    ea = ea2
    lsda_ptr = 0
    if aug.aug_present:
      augm_len, ea = format_leb128(ea, "Augmentation data length")
      if aug.lsda_encoding != DW_EH_PE_omit:
        lsda_ptr, ea2 = read_enc_val(ea, aug.lsda_encoding, True)
        set_cmt(ea, "L: LSDA pointer=%08X" % lsda_ptr, False)
        if lsda_ptr:
          format_lsda(lsda_ptr, init_loc, False)
        ea = ea2
    instr_length = end_ea - ea
    if instr_length > 0:
      format_cfa(ea, aug.code_align, aug.data_align, aug.fde_encoding, instr_length)
      ea = end_ea # just skip to the end lol
    else:
      print "%08X: insn_len = %d?!" % (ea, instr_length)
  return end_ea

s = get_first_seg()
while s != BADADDR:
  if get_segm_name(s) in [".eh_frame", "__eh_frame"]:
    break
  s = get_next_seg(s)

if s != BADADDR:
  ea = get_segm_start(s)
  endea = get_segm_end(s)
  while ea != BADADDR and ea < endea:
    if get_wide_dword(ea) == 0:
      ea += 4

    ea = format_cie_fde(ea)
