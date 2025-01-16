# Function: Instruction related util functions in IDA Python Plugin
# Author: Crifan Li

import idc

import IDAUtil
import CommonUtil
import Operand


# Update: 20250115
# Link: 
class Instruction:
  branchToStr = "BranchTo"
  # toStr = "to"
  toStr = "To"
  # addStr = "add"
  addStr = "Add"

  def __init__(self, addr, name, operands):
    self.addr = addr
    self.disAsmStr = IDAUtil.ida_getDisasmStr(addr)
    # print("self.disAsmStr=%s" % self.disAsmStr)
    self.name = name
    self.operands = operands

  def __str__(self):
    # operandsAllStr = Operand.listToStr(self.operands)
    # print("operandsAllStr=%s" % operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,name=%s,operands=%s>" % (self.addr, self.name, operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,disAsmStr=%s>" % (self.addr, self.disAsmStr)
    curInstStr = "<Instruction: 0x%X: %s>" % (self.addr, self.disAsmStr)
    # print("curInstStr=%s" % curInstStr)
    return curInstStr

  @staticmethod
  def listToStr(instList):
    instContentStrList = [str(eachInst) for eachInst in instList]
    instListAllStr = ", ".join(instContentStrList)
    instListAllStr = "[%s]" % instListAllStr
    return instListAllStr

  @staticmethod
  def parse(addr):
    CommonUtil.logDebug("Instruction: parsing 0x%X", addr)
    parsedInst = None

    instName = idc.print_insn_mnem(addr)
    CommonUtil.logDebug("instName=%s", instName)

    curOperandIdx = 0
    curOperandVaild = True
    operandList = []
    while curOperandVaild:
      CommonUtil.logSubSubStr("[%d]" % curOperandIdx)
      curOperand = idc.print_operand(addr, curOperandIdx)
      CommonUtil.logDebug("curOperand=%s", curOperand)
      curOperandType = idc.get_operand_type(addr, curOperandIdx)
      CommonUtil.logDebug("curOperandType=%d", curOperandType)
      curOperandValue = idc.get_operand_value(addr, curOperandIdx)
      CommonUtil.logDebug("curOperandValue=%s=0x%X", curOperandValue, curOperandValue)
      curOperand = Operand(curOperand, curOperandType, curOperandValue)
      CommonUtil.logDebug("curOperand=%s", curOperand)
      if curOperand.isValid():
        operandList.append(curOperand)
      else:
        CommonUtil.logDebug("End of operand for invalid %s", curOperand)
        curOperandVaild = False

      CommonUtil.logDebug("curOperandVaild=%s", curOperandVaild)
      curOperandIdx += 1

    if operandList:
      parsedInst = Instruction(addr=addr, name=instName, operands=operandList)
    CommonUtil.logDebug("parsedInst=%s", parsedInst)
    CommonUtil.logDebug("operandList=%s", Operand.listToStr(operandList))
    return parsedInst

  def isInst(self, instName):
    isMatchInst = False
    if self.name:
      if (instName.lower() == self.name.lower()):
        isMatchInst = True
    return isMatchInst

  @property
  def contentStr(self):
    """
    convert to meaningful string of Instruction real action / content
    """
    contentStr = ""

    # isDebug = False
    # isDebug = True

    CommonUtil.logDebug("----- To contentStr: %s ----- ", self)

    operandNum = len(self.operands)
    CommonUtil.logDebug("operandNum=%s", operandNum)
    
    isPairInst = self.isStp() or self.isLdp()
    CommonUtil.logDebug("isPairInst=%s", isPairInst)
    if not isPairInst:
      if operandNum >= 1:
        dstOperand = self.operands[0]
        CommonUtil.logDebug("dstOperand=%s", dstOperand)
        dstOperandStr = dstOperand.contentStr
        CommonUtil.logDebug("dstOperandStr=%s", dstOperandStr)

      if operandNum >= 2:
        srcOperand = self.operands[1]
        CommonUtil.logDebug("srcOperand=%s", srcOperand)
        srcOperandStr = srcOperand.contentStr
        CommonUtil.logDebug("srcOperandStr=%s", srcOperandStr)
    
    if self.isBl():
      if operandNum == 1:
        # <Instruction: 0xE3C8: BL _swift_getInitializedObjCClass>
        dstOperandOperand = dstOperand.operand
        CommonUtil.logDebug("dstOperandOperand=%s", dstOperandOperand)
        contentStr = "%s%s" % (Instruction.branchToStr, dstOperandOperand)

    if self.isMov() or self.isFmov():
      # MOV X0, X24
      # FMOV D4, #-3.0

      if operandNum == 2:
        contentStr = "%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperandStr)
        # print("contentStr=%s" % contentStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of MOV/FMOV")
    elif self.isAdd() or self.isFadd():
      # <Instruction: 0x10235D574: ADD X0, X19, X8; location>
      # # print("is ADD: self=%s" % self)
      # instName = self.name
      # # print("instName=%s" % instName)
      # instOperandList = self.operands
      # # print("instOperandList=%s" % Operand.listToStr(instOperandList))
      if operandNum == 3:
        # <Instruction: 0x10235D574: ADD X0, X19, X8; location>
        # <Instruction: 0xE3C4: ADD X0, X0, #_OBJC_CLASS_$__TtC11XxxxXxxXxxx26ApiInitiateRechargeRequest@PAGEOFF>
        extracOperand = self.operands[2]
        # print("extracOperand=%s" % extracOperand)
        extraOperandStr = extracOperand.contentStr
        # print("extraOperandStr=%s" % extraOperandStr)
        contentStr = "%s%s%s%s%s" % (srcOperandStr, Instruction.addStr, extraOperandStr, Instruction.toStr, dstOperandStr)

      # TODO: add case operand == 2
    elif self.isLdr():
      # LDR X0, [SP,#arg_18];
      if operandNum == 2:
        contentStr = "%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperandStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        CommonUtil.logInfo("TODO: add support operand > 2 of LDR")
    elif self.isStr():
      # STR XZR, [X19,X8]
      if operandNum == 2:
        contentStr = "%s%s%s" % (dstOperandStr, Instruction.toStr, srcOperandStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        CommonUtil.logInfo("TODO: add support operand > 2 of STR")
    elif self.isStp():
      # <Instruction: 0x10235D6B4: STP X8, X9, [SP,#arg_18]>
      if operandNum == 3:
        srcOperand1 = self.operands[0]
        CommonUtil.logDebug("srcOperand1=%s", srcOperand1)
        srcOperand1Str = srcOperand1.contentStr
        CommonUtil.logDebug("srcOperand1Str=%s", srcOperand1Str)
        srcOperand2 = self.operands[1]
        CommonUtil.logDebug("srcOperand2=%s", srcOperand2)
        srcOperand2Str = srcOperand2.contentStr
        CommonUtil.logDebug("srcOperand2Str=%s", srcOperand2Str)

        dstOperand = self.operands[2]
        CommonUtil.logDebug("dstOperand=%s", dstOperand)
        dstOperandStr = dstOperand.contentStr
        CommonUtil.logDebug("dstOperandStr=%s", dstOperandStr)
        
        contentStr = "%s%s%s%s" % (srcOperand1Str, srcOperand2Str, Instruction.toStr, dstOperandStr)
    elif self.isLdp():
      # <Instruction: 0x10235D988: LDP D0, D1, [X8]>
      # <Instruction: 0x10235D98C: LDP D2, D3, [X8,#0x10]>
      if operandNum == 3:
        dstOperand1 = self.operands[0]
        CommonUtil.logDebug("dstOperand1=%s", dstOperand1)
        dstOperand1Str = dstOperand1.contentStr
        CommonUtil.logDebug("dstOperand1Str=%s", dstOperand1Str)
        dstOperand2 = self.operands[1]
        CommonUtil.logDebug("dstOperand2=%s", dstOperand2)
        dstOperand2Str = dstOperand2.contentStr
        CommonUtil.logDebug("dstOperand2Str=%s", dstOperand2Str)

        srcOperand = self.operands[2]
        CommonUtil.logDebug("srcOperand=%s", srcOperand)
        srcOperandStr = srcOperand.contentStr
        CommonUtil.logDebug("srcOperandStr=%s", srcOperandStr)
        
        contentStr = "%s%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperand1Str, dstOperand2Str)
    elif self.isAdrp():
      if operandNum == 2:
        # <Instruction: 0xE3C0: ADRP X0, #unk_111D000; classType>
        dstOperand1 = self.operands[0]
        CommonUtil.logDebug("dstOperand1=%s", dstOperand1)
        dstOperand1Str = dstOperand1.contentStr
        CommonUtil.logDebug("dstOperand1Str=%s", dstOperand1Str)

        srcOperand = self.operands[1]
        CommonUtil.logDebug("srcOperand=%s", srcOperand)
        srcOperandStr = srcOperand.contentStr
        CommonUtil.logDebug("srcOperandStr=%s", srcOperandStr)

        contentStr = "PageAddr%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperand1Str)

    # TODO: add other Instruction support: SUB/STR/...
    CommonUtil.logDebug("contentStr=%s", contentStr)
    return contentStr

  def isMov(self):
    return self.isInst("MOV")

  def isFmov(self):
    return self.isInst("FMOV")

  def isRet(self):
    return self.isInst("RET")

  def isB(self):
    return self.isInst("B")

  def isBr(self):
    return self.isInst("BR")

  def isBl(self):
    return self.isInst("BL")

  def isBlr(self):
    return self.isInst("BLR")

  def isBranch(self):
    # TODO: support more: BRAA / ...
    return self.isB() or self.isBr() or self.isBl() or self.isBlr()

  def isAdd(self):
    return self.isInst("ADD")

  def isFadd(self):
    return self.isInst("FADD")

  def isSub(self):
    return self.isInst("SUB")

  def isStr(self):
    return self.isInst("STR")

  def isStp(self):
    return self.isInst("STP")

  def isLdp(self):
    return self.isInst("LDP")

  def isLdr(self):
    return self.isInst("LDR")

  def isAdrp(self):
    return self.isInst("ADRP")
