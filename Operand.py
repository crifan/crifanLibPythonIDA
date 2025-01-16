# Function: Operand related util functions in IDA Python Plugin
# Author: Crifan Li

import re

import CommonUtil
import OperandType
import ARMUtil

# Update: 20250115
# Link: 
class Operand:
  # addStr = "add"
  # addStr = "Add"
  offStr = "Off" # Offset=Index
  # valStr = "val"
  valStr = "Val"

  def __init__(self, operand, type, value):
    self.operand = operand
    self.type = type
    self.value = value

    # for o_displ / o_phrase
    self.baseReg = None
    self.indexReg = None
    # for o_displ
    self.displacement = None
    self.displ_addr = None

    self._postInit()
  
  def _postInit(self):
    # print("")
    CommonUtil.logDebug("_postInit: self.operand=%s", self.operand)
    if self.isDispl():
      # o_displ    = 4        # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
      # [SP,#arg_18]
      # [X20,#0x50]
      # print("self.operand=%s" % self.operand)
      # displMatch = re.search("\[(?P<baseReg>\w+),(?P<displacement>#[\w\-\.]+)\]", self.operand)
      # [X9]
      # displMatch = re.search("\[(?P<baseReg>\w+)(,(?P<displacement>#[\w\-\.]+))?\]", self.operand)
      # curOperand=[SP,#-0x10+var_s0]!
      displMatch = re.search("\[(?P<baseReg>\w+)(,(?P<displacement>#[\w\-\.\+]+))?\]!?", self.operand)
      CommonUtil.logDebug("displMatch=%s", displMatch)
      if displMatch:
        self.baseReg = displMatch.group("baseReg")
        CommonUtil.logDebug("self.baseReg=%s", self.baseReg)
        self.displacement = displMatch.group("displacement")
        CommonUtil.logDebug("self.displacement=%s", self.displacement)

      if not displMatch:
        # LDP X29, X30, [SP+var_s0],#0x10
        # curOperand=[SP+var_s0],#0x10
        displMatch = re.search("\[(?P<baseReg>\w+)\+(?P<displacement>\w+)\],#(?P<displ_addr>)", self.operand)
        CommonUtil.logDebug("displMatch=%s", displMatch)

        if displMatch:
          self.baseReg = displMatch.group("baseReg")
          CommonUtil.logDebug("self.baseReg=%s", self.baseReg)
          self.displacement = displMatch.group("displacement")
          CommonUtil.logDebug("self.displacement=%s", self.displacement)
          self.displ_addr = displMatch.group("displ_addr")
          CommonUtil.logDebug("self.displ_addr=%s", self.displ_addr)

    elif self.isPhrase():
      # o_phrase   = 3        # Memory Ref [Base Reg + Index Reg]    phrase
      # [X19,X8]
      # print("self.operand=%s" % self.operand)
      phraseMatch = re.search("\[(?P<baseReg>\w+),(?P<indexReg>\w+)\]", self.operand)
      # print("phraseMatch=%s" % phraseMatch)
      if phraseMatch:
        self.baseReg = phraseMatch.group("baseReg")
        # print("self.baseReg=%s" % self.baseReg)
        self.indexReg = phraseMatch.group("indexReg")
        # print("self.indexReg=%s" % self.indexReg)

  def __str__(self):
    valStr = ""
    if self.value <= 0:
      valStr = "%s" % self.value
    else:
      valStr = "0x%X" % self.value
    # curOpStr = "<Operand: op=%s,type=%d,val=%s>" % (self.operand, self.type, valStr)
    # curOpStr = "<Operand: op=%s,type=%d,val=%s, baseReg=%s,indexReg=%s,displ=%s>" % (self.operand, self.type, valStr, self.baseReg, self.indexReg, self.displacement)
    extraInfo = ""
    if self.isDispl():
      extraInfo = ",bsReg=%s,idxReg=%s,displ=%s" % (self.baseReg, self.indexReg, self.displacement)
    elif self.isPhrase():
      extraInfo = ",bsReg=%s,idxReg=%s" % (self.baseReg, self.indexReg)
    curOpStr = "<Operand: op=%s,type=%d,val=%s%s>" % (self.operand, self.type, valStr, extraInfo)
    # print("curOpStr=%s" % curOpStr)
    return curOpStr

  @staticmethod
  def listToStr(operandList):
    # operandStrList = []
    # for curOperand in operandList:
    #   if curOperand:
    #     curOperandStr = "%s" % curOperand
    #   else:
    #     curOperandStr = ""
    #   # print("curOperandStr=%s" % curOperandStr)
    #   operandStrList.append(curOperandStr)
    operandStrList = [str(eachOperand) for eachOperand in operandList]
    operandListAllStr = ", ".join(operandStrList)
    operandListAllStr = "[%s]" % operandListAllStr
    return operandListAllStr

  def isReg(self):
    return self.type == OperandType.o_reg

  def isImm(self):
    return self.type == OperandType.o_imm

  def isDispl(self):
    return self.type == OperandType.o_displ

  def isPhrase(self):
    return self.type == OperandType.o_phrase

  def isNear(self):
    return self.type == OperandType.o_near

  def isIdpspec0(self):
    #   o_idpspec0 = 8        # Processor specific type
    return self.type == OperandType.o_idpspec0

  def isValid(self):
    isDebug = False

    # isValidOperand = bool(self.operand)
    # print("isValidOperand=%s" % isValidOperand)
    # if isValidOperand:
    isValidOperand = False

    if isDebug:
      print("self.operand=%s" % self.operand)

    if self.operand:
      if self.isImm():
        # #0x20200A2C
        # #0x2020
        # #arg_20
        # isMatchImm = re.match("^#[0-9a-fA-FxX]+$", self.operand)
        # #-3.0
        # isMatchImm = re.match("^#\w+$", self.operand)
        # isMatchImm = re.match("^#[\w\-\.]+$", self.operand)
        # curOperand=#_OBJC_CLASS_$__TtC11XxxxXxxXxxx26ApiInitiateRechargeRequest@PAGEOFF
        isMatchImm = re.match("^#[\w\-\.\$\@]+$", self.operand)
        CommonUtil.logDebug("isMatchImm=%s" % isMatchImm)
        isValidOperand = bool(isMatchImm)
        CommonUtil.logDebug("isValidOperand=%s" % isValidOperand)
      elif self.isReg():
        # X0/X1
        # D8/D4
        # Special: XZR/WZR
        regNameUpper = self.operand.upper()
        # print("regNameUpper=%s" % regNameUpper)
        # isMatchReg = re.match("^[XD]\d+$", regNameUpper)
        # isMatchReg = re.match("^[XDW]\d+$", regNameUpper)
        isMatchReg = re.match("^([XDW]\d+)|(XZR)|(WZR)$", regNameUpper)
        CommonUtil.logDebug("isMatchReg=%s" % isMatchReg)
        isValidOperand = bool(isMatchReg)
        CommonUtil.logDebug("isValidOperand=%s" % isValidOperand)
        if not isValidOperand:
          isValidOperand = regNameUpper in ARMUtil.ArmSpecialRegNameList
      elif self.isDispl():
        # o_displ    = 4        # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
        # curOperand=<Operand: op=[SP,#arg_18],type=4,val=0x18>
        # if self.baseReg and (not self.indexReg) and self.displacement:
        # curOperand=<Operand: op=[X9],type=4,val=0x0>
        CommonUtil.logDebug("self.baseReg=%s, self.indexReg=%s, self.displacement=%s" % (self.baseReg, self.indexReg, self.displacement))

        if self.baseReg and (not self.indexReg):
          # Note: self.displacement is None / Not-None
          # TODO: add more type support, like indexReg not None
          isValidOperand = True
      elif self.isPhrase():
        # curOperand=<Operand: op=[X19,X8],type=3,val=0x94>
        CommonUtil.logDebug("self.baseReg=%s, self.indexReg=%s" % (self.baseReg, self.indexReg))
        if self.baseReg and self.indexReg:
          isValidOperand = True
      elif self.isNear():
        # o_near     = 7        # Immediate Near Address (CODE)        addr
        # curOperand=<Operand: op=_objc_copyWeak,type=7,val=0x1024ABBD0>
        CommonUtil.logDebug("self.value=%s" % self.value)

        if self.value:
          # jump to some (non 0) address -> consider is valid
          isValidOperand = True
      elif self.isIdpspec0():
        isValidOperand = True

    # print("isValidOperand=%s" % isValidOperand)

    # isValidType = self.type != OperandType.o_void
    # isValidValue = self.value >= 0
    # isValidAll = isValidOperand and isValidType and isValidValue
    # isValidTypeValue = False
    # if self.isReg() or self.isImm():
    #   isValidTypeValue = self.value >= 0
    # elif self.isIdpspec0():
    #   isValidTypeValue = self.value == -1

    if self.isIdpspec0():
      isValidTypeValue = self.value == -1
    else:
      isValidType = self.type != OperandType.o_void
      isValidValue = self.value >= 0
      isValidTypeValue = isValidType and isValidValue
    isValidAll = isValidOperand and isValidTypeValue

    if isDebug:
      print("Operand isValidAll=%s" % isValidAll)
    return isValidAll

  def isInvalid(self):
    return not self.isValid()
  
  @property
  def immVal(self):
    curImmVal = None
    if self.isImm():
      curImmVal = self.value
      # print("curImmVal=%s" % curImmVal)
    return curImmVal
  
  @property
  def immValHex(self):
    curImmValHex = ""
    if self.immVal != None:
      curImmValHex = "0x%X" % self.immVal
      # print("curImmValHex=%s" % curImmValHex)
    return curImmValHex

  @property
  def regName(self):
    curRegName = None
    if self.isReg():
      curRegName = self.operand
    return curRegName

  @property
  def contentStr(self):
    contentStr = ""
    if self.isReg():
      # print("isReg")
      contentStr = self.regName
    elif self.isImm():
      # print("isImm")
      # if 0 == self.immVal:
      # for 0 <= x < 8, not add 0x prefix, eg: 0x7 -> 7
      if (self.immVal >= 0) and (self.immVal < 8):
        # contentStr = "0"
        contentStr = "%X" % self.immVal
      else:
        contentStr = self.immValHex
    elif self.isIdpspec0():
        contentStr = self.operand
    elif self.isDispl():
        # [SP,#arg_18]
        # print("self.displacement=%s" % self.displacement)
        if self.displacement:
          displacementStr = ""
          if self.value != None:
            if (self.value >= 0) and (self.value < 8):
              displacementStr = "%X" % self.value
            else:
              displacementStr = "0x%X" % self.value
          # print("displacementStr=%s" % displacementStr)
          contentStr = "%s%s%s%s" % (self.baseReg, Operand.offStr, displacementStr, Operand.valStr)
        else:
          contentStr = "%s%s" % (self.baseReg, Operand.valStr)
    elif self.isPhrase():
      # [X19,X8]
      contentStr = "%s%s%s%s" % (self.baseReg, Operand.offStr, self.indexReg, Operand.valStr)

    # remove invalid char
    # <Operand: op=W0,UXTB,type=8,val=-1>
    # W0,UXTB -> W0UXTB
    contentStr = contentStr.replace(",", "")
    # X21,LSL#32
    # X8,ASR#29
    contentStr = contentStr.replace("#", "")

    # TODO: add more case

    # print("contentStr=%s" % contentStr)
    return contentStr

  @property
  def regIdx(self):
    curRegIdx = None
    if self.isReg():
      # TODO: extract reg idx, 
      # eg: X0 -> 0, X4 -> 4
      # note: additonal: D0 -> 0, D8 -> 8 ?
      curRegIdx = 0
    return curRegIdx
