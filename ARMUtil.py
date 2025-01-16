# Function: ARM related util functions in IDA Python Plugin
# Author: Crifan Li

# Update: 20250115
# Link: 
class ARMUtil:
  ArmSpecialRegNameList = [
    "SB",
    "TR",
    "XR",
    "IP",
    "IP0",
    "IP1",
    "PR",
    "SP",
    "FP",
    "LR",
    "PC",
  ]

  PrologueEpilogueRegList = [
    "X19",
    "X20",
    "X21",
    "X22",
    "X23",
    "X24",
    "X25",
    "X26",
    "X27",
    "X28",
    "X29",
    "X30",

    "D8",
    "D9",
  ]
