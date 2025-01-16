# Function: Crifan's common use IDA related functions
# Author: Crifan Li

import re
import os

import idc
import idaapi
import idautils
import ida_nalt
import ida_segment
import ida_name
import ida_bytes
import ida_funcs

import CommonUtil
import ARMUtil
import Instruction

# Update: 20250115
# Link: https://github.com/crifan/crifanLibPythonIDA/blob/main/IDAUtil.py
class IDAUtil:
  # IDA Python API:
  #   https://www.hex-rays.com/products/ida/support/idapython_docs/index.html
  #
  #   idc
  #     https://hex-rays.com//products/ida/support/idapython_docs/idc.html
  #   ida_name
  #     https://hex-rays.com/products/ida/support/idapython_docs/ida_name.html


  IdaReservedStr = [
    "class",
    "id",
    "const",
    "char",
    "void",
    "return",
    "private",
    "namespace",
    "catch",
    "do",
    "while",
    "new",
    "default",
    "for",
  ]

  # for rename
  funcNameP_X29X30_STP = r"_(?P<stpName>X29X30ToSPOff[^_]+)"
  funcNameP_X29X30_LDP = r"_(?P<ldpName>SPOff[^_]+ToX29X30)"

  #-------------------------------------------------------------------------------
  # iOS Util Function
  #-------------------------------------------------------------------------------

  def ida_getFunctionComment(idaAddr, repeatable=False):
    """
    Get function comment
    """
    # funcStruct = ida_funcs.get_func(idaAddr)
    # print("[0x%X] -> funcStruct=%s" % (idaAddr, funcStruct))
    # curFuncCmt = ida_funcs.get_func_cmt(funcStruct, repeatable)
    curFuncCmt = idc.get_func_cmt(idaAddr, repeatable)
    # print("[0x%X] -> curFuncCmt=%s" % (idaAddr, curFuncCmt))
    return curFuncCmt

  def ida_setFunctionComment(idaAddr, newComment, repeatable=False):
    """
    Set function comment
    """
    setCmtRet = idc.set_func_cmt(idaAddr, newComment, repeatable)
    # print("[0x%X] -> setCmtRet=%s" % (idaAddr, setCmtRet))
    return setCmtRet

  def ida_setComment(idaAddr, commentStr, repeatable=False):
    """
    Set comment for ida address
    """
    isSetCmtOk = ida_bytes.set_cmt(idaAddr, commentStr, repeatable)
    # print("set_cmt: [0x%X] commentStr=%s -> isSetCmtOk=%s" % (idaAddr, commentStr, isSetCmtOk))
    return isSetCmtOk

  # setCmtAddr = 0xF35794
  # # # setCmtAddr = 0xF35798
  # # commentStr = "-[WamEventBotJourney is_ui_surface_set], -[WamEventCallUserJourney is_ui_surface_set], -[WamEventGroupJourney is_ui_surface_set], -[WamEventIncallParticipantPickerShown is_ui_surface_set], -[WamEventSelectParticipantFromPicker is_ui_surface_set]"
  # # # commentStr = ""
  # # # ida_setComment(setCmtAddr, commentStr)
  # # newFuncCmt = commentStr
  # # oldFuncCmt = ida_getFunctionComment(setCmtAddr)
  # # print("oldFuncCmt=%s" % oldFuncCmt)
  # # if oldFuncCmt:
  # #   newFuncCmt = "%s\n%s" % (oldFuncCmt, newFuncCmt)
  # # print("newFuncCmt=%s" % newFuncCmt)
  # # setCmdRet = ida_setFunctionComment(setCmtAddr, newFuncCmt)
  # setCmdRet = ida_setFunctionComment(setCmtAddr, "")
  # print("setCmdRet=%s" % setCmdRet)
  # ssssss

  def ida_getXrefsToList(idaAddr):
    """
    get XrefsTo info dict list from ida address
    eg:
      0x139CFBF -> [{'type': 1, 'typeName': 'Data_Offset', 'isCode': 0, 'from': 26301800, 'to': 20565951}]
    """
    xrefToInfoDictList = []
    refToGenerator = idautils.XrefsTo(idaAddr)
    # print("refToGenerator=%s" % refToGenerator)
    for eachXrefTo in refToGenerator:
      # print("eachXrefTo=%s" % eachXrefTo)
      xrefType = eachXrefTo.type
      # print("xrefType=%s" % xrefType)
      xrefTypeName = idautils.XrefTypeName(xrefType)
      # print("xrefTypeName=%s" % xrefTypeName)
      xrefIsCode = eachXrefTo.iscode
      # print("xrefIsCode=%s" % xrefIsCode)
      xrefFrom = eachXrefTo.frm
      # print("xrefFrom=0x%X" % xrefFrom)
      xrefTo = eachXrefTo.to
      # print("xrefTo=0x%X" % xrefTo)
      curXrefToInfoDict = {
        "type": xrefType,
        "typeName": xrefTypeName,
        "isCode": xrefIsCode,
        "from": xrefFrom,
        "to": xrefTo,
      }
      xrefToInfoDictList.append(curXrefToInfoDict)
    # print("idaAddr=0x%X -> xrefToInfoDictList=%s" % (idaAddr, xrefToInfoDictList))
    return xrefToInfoDictList

  def findClassFromSelector(selectorStr):
    """
    find ObjC Class name (and function name) from selector string
    eg:
      "setCellsEligibleForExpansion:" -> [{'objcClassName': 'WAAccordionTableView', 'objcFuncName': '-[WAAccordionTableView setCellsEligibleForExpansion:]'}]
    """
    foundItemList = []

    # idaSelStr = re.sub(":", "_", selectorStr)
    # idaSelStr = "sel_%s" % idaSelStr
    idaSelStr = "sel_%s" % selectorStr
    CommonUtil.logDebug("idaSelStr=%s", idaSelStr)
    # idaAddr = ida_name.get_name_ea(idaSelStr)
    idaAddr = idc.get_name_ea_simple(idaSelStr)
    CommonUtil.logDebug("idaAddr=0x%X", idaAddr)

    # realAddr = 0x139CFA1
    # foundObjcMethname = idc.get_name(realAddr)
    # logDebug("realAddr=0x%X -> foundObjcMethname=%s" % (realAddr, foundObjcMethname))

    # refToGenerator = idautils.XrefsTo(idaAddr)
    # logDebug("refToGenerator=%s" % refToGenerator)
    # for eachXrefTo in refToGenerator:
    xrefToInfoDictList = IDAUtil.ida_getXrefsToList(idaAddr)
    CommonUtil.logDebug("xrefToInfoDictList=%s", xrefToInfoDictList)
    for eachXrefToInfoDict in xrefToInfoDictList:
      CommonUtil.logDebug("eachXrefToInfoDict=%s" % eachXrefToInfoDict)
      xrefFrom = eachXrefToInfoDict["from"]
      CommonUtil.logDebug("xrefFrom=%s" % xrefFrom)

      CommonUtil.logDebug("--- Xref From [0x%X] ---" % xrefFrom)
      xrefFromName = idc.get_name(xrefFrom)
      CommonUtil.logDebug("xrefFromName=%s" % xrefFromName)
      # xrefFromType = idc.get_type(xrefFrom)
      # logDebug("xrefFromType=%s" % xrefFromType)
      # xrefFromTinfo = idc.get_tinfo(xrefFrom)
      # logDebug("xrefFromTinfo=%s" % xrefFromTinfo)
      xrefFromSegName = idc.get_segm_name(xrefFrom)
      CommonUtil.logDebug("xrefFromSegName=%s" % xrefFromSegName)
      xrefFromItemSize = idc.get_item_size(xrefFrom)
      CommonUtil.logDebug("xrefFromItemSize=%s" % xrefFromItemSize)

      # (1) __objc_const:000000000183B5F8  __objc2_meth <sel_setCellsEligibleForExpansion_, aV240816_3, \ ;-[WAAccordionTableView setCellsEligibleForExpansion:] ...
      #     __objc_const:000000000183B5F8  __WAAccordionTableView_setCellsEligibleForExpansion__>
      # isValidObjcSegment = xrefFromSegName == "__objc_const"
      # (2) __objc_data:00000000019C8F18                 __objc2_meth <sel_initWithDependencyInversion_, a240816_5, \ ; -[WAContext initWithDependencyInversion:] ...
      #     __objc_data:00000000019C8F18                               __WAContext_initWithDependencyInversion__>
      isValidObjcSegment = (xrefFromSegName == "__objc_const") or (xrefFromSegName == "__objc_data")
      CommonUtil.logDebug("isValidObjcSegment=%s" % isValidObjcSegment)
      Objc2MethSize = 24
      isObjcMethodSize = xrefFromItemSize == Objc2MethSize
      CommonUtil.logDebug("isObjcMethodSize=%s" % isObjcMethodSize)
      isObjcConstMeth = isValidObjcSegment and isObjcMethodSize
      CommonUtil.logDebug("isObjcConstMeth=%s" % isObjcConstMeth)

      if isObjcConstMeth:
        # methodSignatureAddr = xrefFrom + 0x8
        # logDebug("methodSignatureAddr=0x%X" % methodSignatureAddr)
        # isRepeatable = False
        # xrefFromCmt = ida_bytes.get_cmt(xrefFrom, isRepeatable)
        # logDebug("xrefFromCmt=%s" % xrefFromCmt)
        # methodSignatureCmt = ida_bytes.get_cmt(methodSignatureAddr, isRepeatable)
        # logDebug("methodSignatureCmt=%s" % methodSignatureCmt)

        methodImplementAddr = xrefFrom + 0x10
        CommonUtil.logDebug("methodImplementAddr=0x%X" % methodImplementAddr)
        methodImplementValueAddr = ida_bytes.get_qword(methodImplementAddr)
        CommonUtil.logDebug("methodImplementValueAddr=0x%X" % methodImplementValueAddr)
        objcMethodName = None
        methodImplementValueName = idc.get_name(methodImplementValueAddr)
        CommonUtil.logDebug("methodImplementValueName=%s" % methodImplementValueName)
        if methodImplementValueName:
          objcMethodName = methodImplementValueName
        else:
          methodImplementValueFuncName = idc.get_func_name(methodImplementValueAddr)
          CommonUtil.logDebug("methodImplementValueFuncName=%s" % methodImplementValueFuncName)
          objcMethodName = methodImplementValueFuncName
        
        if objcMethodName:
          isObjcFuncName, isClass, foundClassName, foundSelectorStr = IDAUtil.isObjcFunctionName(objcMethodName)
          CommonUtil.logDebug("objcMethodName=%s -> isObjcFuncName=%s, isClass=%s, foundClassName=%s, selectorStr=%s" % (objcMethodName, isObjcFuncName, isClass, foundClassName, foundSelectorStr))
          if isObjcFuncName:
            if selectorStr == foundSelectorStr:
              className = foundClassName
              # break
              curItemDict = {
                "objcClassName": className,
                "objcFuncName": objcMethodName,
              }
              foundItemList.append(curItemDict)
              CommonUtil.logDebug("foundItemList=%s" % foundItemList)

    CommonUtil.logDebug("selectorStr=%s -> foundItemList=%s" % (selectorStr, foundItemList))
    return foundItemList

  # # # selectorStr = "setCellsEligibleForExpansion:"
  # # # selectorStr = "setCenter:"
  # # # selectorStr = "sameDeviceCheckRequestURLWithOfflineExposures:offlineMetrics:pushToken:tokenReadError:"
  # # # selectorStr = "initWithDependencyInversion:" # -[WAContext initWithDependencyInversion:]
  # # # selectorStr = "getChannel" # total 736
  # # # # -[WamEventAutoupdateSetupAction getChannel]
  # # # # -[WamEventAvatarBloksLaunch getChannel]
  # selectorStr = "setQuery:"
  # # -[FMStatement setQuery:]
  # # -[FMResultSet setQuery:]
  # foundItemList = findClassFromSelector(selectorStr)
  # print("selectorStr=%s -> foundItemList: %s, count=%d" % (selectorStr, foundItemList, len(foundItemList)))
  # sssss

  ################################################################################
  # IDA Util Function
  ################################################################################

  #-------------------- need call IDA api --------------------

  def ida_getInfo():
    """
    get IDA info
    """
    info = idaapi.get_inf_structure()
    # print("info=%s" % info)
    return info

  def ida_printInfo(info):
    """
    print IDA info
    """
    version = info.version
    print("version=%s" % version)
    is64Bit = info.is_64bit()
    print("is64Bit=%s" % is64Bit)
    procName = info.procname
    print("procName=%s" % procName)
    entryPoint = info.start_ea
    print("entryPoint=0x%X" % entryPoint)
    baseAddr = info.baseaddr
    print("baseAddr=0x%X" % baseAddr)

  def ida_printAllImports():
    """
    print all imports lib and functions inside lib"""
    nimps = ida_nalt.get_import_module_qty()
    print("Found %d import(s)..." % nimps)
    for i in range(nimps):
      name = ida_nalt.get_import_module_name(i)
      if not name:
        print("Failed to get import module name for [%d] %s" % (i, name))
        name = "<unnamed>"
      else:
        print("[%d] %s" % (i, name))

      def imp_cb(ea, name, ordinal):
          if not name:
              print("%08x: ordinal #%d" % (ea, ordinal))
          else:
              print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
          # True -> Continue enumeration
          # False -> Stop enumeration
          return True
      ida_nalt.enum_import_names(i, imp_cb)

  def ida_printSegment(curSeg):
    """
    print segment info
      Note: in IDA, segment == section
    """
    segName = curSeg.name
    # print("type(segName)=%s" % type(segName))
    segSelector = curSeg.sel
    segStartAddr = curSeg.start_ea
    segEndAddr = curSeg.end_ea
    print("Segment: [0x%X-0x%X] name=%s, selector=%s : seg=%s" % (segStartAddr, segEndAddr, segName, segSelector, curSeg))

  def ida_getSegmentList():
    """
    get segment list
    """
    segList = []
    segNum = ida_segment.get_segm_qty()
    for segIdx in range(segNum):
      curSeg = ida_segment.getnseg(segIdx)
      # print("curSeg=%s" % curSeg)
      segList.append(curSeg)
      # ida_printSegment(curSeg)
    return segList

  def ida_testGetSegment():
    """
    test get segment info
    """
    # textSeg = ida_segment.get_segm_by_name("__TEXT")
    # dataSeg = ida_segment.get_segm_by_name("__DATA")

    # ida_getSegmentList()

    # NAME___TEXT = "21"
    # NAME___TEXT = 21
    # NAME___TEXT = "__TEXT,__text"
    # NAME___TEXT = "__TEXT:__text"
    # NAME___TEXT = ".text"

    """
      __TEXT,__text
      __TEXT,__stubs
      __TEXT,__stub_helper
      __TEXT,__objc_stubs
      __TEXT,__const
      __TEXT,__objc_methname
      __TEXT,__cstring
      __TEXT,__swift5_typeref
      __TEXT,__swift5_protos
      __TEXT,__swift5_proto
      __TEXT,__swift5_types
      __TEXT,__objc_classname
      __TEXT,__objc_methtype
      __TEXT,__gcc_except_tab
      __TEXT,__ustring
      __TEXT,__unwind_info
      __TEXT,__eh_frame
      __TEXT,__oslogstring

      __DATA,__got
      __DATA,__la_symbol_ptr
      __DATA,__mod_init_func
      __DATA,__const
      __DATA,__cfstring
      __DATA,__objc_classlist
      __DATA,__objc_catlist
      __DATA,__objc_protolist
      __DATA,__objc_imageinfo
      __DATA,__objc_const
      __DATA,__objc_selrefs
      __DATA,__objc_protorefs
      __DATA,__objc_classrefs
      __DATA,__objc_superrefs
      __DATA,__objc_ivar
      __DATA,__objc_data
      __DATA,__data
      __DATA,__objc_stublist
      __DATA,__swift_hooks
      __DATA,__swift51_hooks
      __DATA,__s_async_hook
      __DATA,__swift56_hooks
      __DATA,__thread_vars
      __DATA,__thread_bss
      __DATA,__bss
      __DATA,__common
    """

    # __TEXT,__text
    NAME___text = "__text"
    textSeg = ida_segment.get_segm_by_name(NAME___text)
    print("textSeg: %s -> %s" % (NAME___text, textSeg))
    IDAUtil.ida_printSegment(textSeg)

    # __TEXT,__objc_methname
    NAME___objc_methname = "__objc_methname"
    objcMethNameSeg = ida_segment.get_segm_by_name(NAME___objc_methname)
    print("objcMethNameSeg: %s -> %s" % (NAME___objc_methname, objcMethNameSeg))
    IDAUtil.ida_printSegment(objcMethNameSeg)

    # __DATA,__got
    NAME___got = "__got"
    gotSeg = ida_segment.get_segm_by_name(NAME___got)
    print("gotSeg: %s -> %s" % (NAME___got, gotSeg))
    IDAUtil.ida_printSegment(gotSeg)

    # __DATA,__data
    # NAME___DATA = "22"
    # NAME___DATA = 22
    NAME___DATA = "__data"
    dataSeg = ida_segment.get_segm_by_name(NAME___DATA)
    print("dataSeg: %s -> %s" % (NAME___DATA, dataSeg))
    IDAUtil.ida_printSegment(dataSeg)

    # exist two one: __TEXT,__const / __DATA,__const
    NAME___const = "__const"
    constSeg = ida_segment.get_segm_by_name(NAME___const)
    print("constSeg: %s -> %s" % (NAME___const, constSeg))
    IDAUtil.ida_printSegment(constSeg)

  def ida_getDemangledName(origSymbolName):
    """
    use IDA to get demangled name for original symbol name
    """
    retName = origSymbolName
    # demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DN))
    # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
    demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
    if demangledName:
      retName = demangledName

    # do extra post process:
    # remove/replace invalid char for non-objc function name
    isNotObjcFuncName = not IDAUtil.isObjcFunctionName(retName)
    # print("isNotObjcFuncName=%s" % isNotObjcFuncName)
    if isNotObjcFuncName:
      retName = retName.replace("?", "")
      retName = retName.replace(" ", "_")
      retName = retName.replace("*", "_")
    # print("origSymbolName=%s -> retName=%s" % (origSymbolName, retName))
    return retName

  def ida_getFunctionEndAddr(funcAddr):
    """
    get function end address
      Example:
        0x1023A2534 -> 0x1023A2540
    """
    funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
    return funcAddrEnd

  def ida_getFunctionSize(funcAddr):
    """
    get function size
      Example:
        0x1023A2534 -> 12
    """
    funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
    funcAddStart = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_START)
    funcSize = funcAddrEnd - funcAddStart
    return funcSize

  def ida_getFunctionName(funcAddr):
    """
    get function name
      Exmaple:
        0x1023A2534 -> "sub_1023A2534"
        0xF9D260 -> "objc_msgSend$initWithKeyValueStore_namespace_binaryCoders_X22toX0_X23toX2_X24toX4_EF8C"
    """
    funcName = idc.get_func_name(funcAddr)
    return funcName

  def ida_getName(curAddr):
    """
    get name
      Exmaple:
        0xF9D260 -> "_objc_msgSend$initWithKeyValueStore:namespace:binaryCoders:"
    """
    addrName = idc.get_name(curAddr)
    return addrName

  def ida_getDisasmStr(funcAddr):
    """
    get disasmemble string
      Exmaple:
        0x1023A2534 -> "MOV X5, X0"
    """
    # method 1: generate_disasm_line
    # disasmLine_forceCode = idc.generate_disasm_line(funcAddr, idc.GENDSM_FORCE_CODE)
    # print("disasmLine_forceCode: type=%s, val=%s" % (type(disasmLine_forceCode), disasmLine_forceCode))
    # disasmLine_multiLine = idc.generate_disasm_line(funcAddr, idc.GENDSM_MULTI_LINE)
    # print("disasmLine_multiLine: type=%s, val=%s" % (type(disasmLine_multiLine), disasmLine_multiLine))

    # method 2: GetDisasm
    disasmLine = idc.GetDisasm(funcAddr)
    # print("disasmLine: type=%s, val=%s" % (type(disasmLine), disasmLine))

    # post process
    # print("disasmLine=%s" % disasmLine)
    # "MOV             X4, X21" -> "MOV X4, X21"
    disasmLine = re.sub("\s+", " ", disasmLine)
    # print("disasmLine=%s" % disasmLine)
    return disasmLine

  def ida_getFunctionAddrList():
    """
    get function address list
    """
    functionIterator = idautils.Functions()
    functionAddrList = []
    for curFuncAddr in functionIterator:
      functionAddrList.append(curFuncAddr)
    return functionAddrList

  def ida_rename(curAddr, newName, retryName=None):
    """
    rename <curAddr> to <newName>. if fail, retry with with <retryName> if not None
      Example:
        0x3B4E28, "X2toX21_X1toX20_X0toX19_4E28", "X2toX21_X1toX20_X0toX19_3B4E28" -> True, "X2toX21_X1toX20_X0toX19_4E28"
    """
    # print("curAddr=0x%X, newName=%s, retryName=%s" % (curAddr, newName, retryName))
    isRenameOk = False
    renamedName = None

    isOk = idc.set_name(curAddr, newName)
    # print("isOk=%s for [0x%X] -> %s" % (isOk, curAddr, newName))
    if isOk == 1:
      isRenameOk = True
      renamedName = newName
    else:
      if retryName:
        isOk = idc.set_name(curAddr, retryName)
        # print("isOk=%s for [0x%X] -> %s" % (isOk, curAddr, retryName))
        if isOk == 1:
          isRenameOk = True
          renamedName = retryName

    # print("isRenameOk=%s, renamedName=%s" % (isRenameOk, renamedName))
    return (isRenameOk, renamedName)

  def ida_getCurrentFolder():
    """
    get current folder for IDA current opened binary file
      Example:
        -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
        -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app/Frameworks/SharedModules.framework
    """
    curFolder = None
    inputFileFullPath = ida_nalt.get_input_file_path()
    # print("inputFileFullPath=%s" % inputFileFullPath)
    if inputFileFullPath.startswith("/var/containers/Bundle/Application"):
      # inputFileFullPath=/var/containers/Bundle/Application/2BE964D4-8DF0-4858-A06D-66CA8741ACDC/WhatsApp.app/WhatsApp
      # -> maybe IDA bug -> after debug settings, output iOS device path, but later no authority to write exported file to it
      # so need to avoid this case, change to output to PC side (Mac) current folder
      curFolder = "."
    else:
      curFolder = os.path.dirname(inputFileFullPath)
    # print("curFolder=%s" % curFolder)

    # debugInputPath = ida_nalt.dbg_get_input_path()
    # print("debugInputPath=%s" % debugInputPath)

    curFolder = os.path.abspath(curFolder)
    # print("curFolder=%s" % curFolder)
    # here work:
    # . -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
    return curFolder

  def isDefaultTypeForObjcMsgSendFunction(funcAddr):
    """
    check is objc_msgSend$xxx function's default type "id(void *, const char *, ...)" or not
    eg:
      0xF3EF8C -> True
        note: funcType=id(void *, const char *, __int64, __int64, ...)
    """
    isDefType = False
    funcType = idc.get_type(funcAddr)
    CommonUtil.logDebug("[0x%X] -> funcType=%s", funcAddr, funcType)
    if funcType:
      defaultTypeMatch = re.search("\.\.\.\)$", funcType)
      CommonUtil.logDebug("defaultTypeMatch=%s", defaultTypeMatch)
      isDefType = bool(defaultTypeMatch)
      CommonUtil.logDebug("isDefType=%s", isDefType)
    return isDefType

  #-------------------- not need call IDA api --------------------

  def isObjcFunctionName(funcName):
    """
    check is ObjC function name or not
    eg:
      "+[WAAvatarStringsActions editAvatar]" -> True, True, "WAAvatarStringsActions", "editAvatar"
      "-[ParentGroupInfoViewController initWithParentGroupChatSession:userContext:recentlyLinkedGroupJIDs:]" -> True, False, "ParentGroupInfoViewController", "initWithParentGroupChatSession:userContext:recentlyLinkedGroupJIDs:"
      "-[OKEvolveSegmentationVC proCard]_116" -> True, False, "OKEvolveSegmentationVC", "proCard"
      "-[WAAvatarStickerUpSellSupplementaryView .cxx_destruct]" -> True, False, "WAAvatarStickerUpSellSupplementaryView", ".cxx_destruct"
      "sub_10004C6D8" -> False, False, None, None
      "protocol witness for RawRepresentable.init(rawValue:) in conformance UIFont.FontWeight" -> False, False, None, None
    """
    isObjcFuncName = False
    isClass = False
    className = None
    selectorStr = None

    objcFuncMatch = re.match("^(?P<classChar>[\-\+])\[(?P<className>\w+) (?P<selectorStr>[\w\.\:]+)\]\w*$", funcName)
    # print("objcFuncMatch=%s" % objcFuncMatch)
    if objcFuncMatch:
      isObjcFuncName = True
      classChar = objcFuncMatch.group("classChar")
      # print("classChar=%s" % classChar)
      if classChar == "+":
        isClass = True
      className = objcFuncMatch.group("className")
      # print("className=%s" % className)
      selectorStr = objcFuncMatch.group("selectorStr")
      # print("selectorStr=%s" % selectorStr)

    # print("funcName=%s -> isObjcFuncName=%s, isClass=%s, className=%s, selectorStr=%s" % (funcName, isObjcFuncName, isClass, className, selectorStr))
    return isObjcFuncName, isClass, className, selectorStr

  def isObjcMsgSendFuncName(funcName):
    """
    check function name is _objc_msgSend$xxx or not
    eg:
      "_objc_msgSend$arrayByAddingObjectsFromArray:" -> True, "arrayByAddingObjectsFromArray:"
      "_objc_msgSend$addObject:_AB00" -> True, "addObject:_AB00"
      "objc_msgSend$initWithKeyValueStore_namespace_binaryCoders_X22toX0_X23toX2_X24toX4" -> True, "initWithKeyValueStore_namespace_binaryCoders_X22toX0_X23toX2_X24toX4"
    """
    isOjbcMsgSend = False
    selectorStr = None
    # _objc_msgSend$arrangedSubviews
    # _objc_msgSend$arrayByAddingObjectsFromArray:
    # _objc_msgSend$arrangeFromView:toView:progress:forwardDirection:
    # objcMsgSendMatch = re.match("^_*objc_msgSend\$(?P<selectorStr>[\w\:]+¸)$", funcName)
    # objcMsgSendMatch = re.match("^_*objc_msgSend\$(?P<selectorStr>[\w\:]+)(?P<renamedAddrSuffix>_[A-Za-z0-9]+)?$", funcName)
    objcMsgSendMatch = re.match("^_*objc_msgSend\$(?P<selectorStr>[\w\:]+)$", funcName)
    # print("objcMsgSendMatch=%s" % objcMsgSendMatch)
    if objcMsgSendMatch:
      selectorStr = objcMsgSendMatch.group("selectorStr")
      # print("selectorStr=%s" % selectorStr)
      isOjbcMsgSend = True
    # print("isOjbcMsgSend=%s, selectorStr=%s" % (isOjbcMsgSend, selectorStr))
    return isOjbcMsgSend, selectorStr

  def isFuncName_TypeMetadataAccessorForAppDelegate(funcName):
    """
    check function name is 'type metadata accessor for AppDelegate_N' or not
    eg:
      type metadata accessor for AppDelegate_5
    """
    isTypeMetadataAccessorForAppDelegate = re.match("type metadata accessor for AppDelegate", funcName)
    return isTypeMetadataAccessorForAppDelegate

  def isFuncName_STP(funcName):
    """
    check function name is contain STP, eg '_X29X30ToSPOffxxx' or not
    eg:
      "ZdlPv_X29X30ToSPOff0xFFFFFFFFFFFFFFF0Val_xxxx_0274" -> True, Match Object
    """
    isStp = False
    stpMatch = None
    stpMatch = re.search(IDAUtil.funcNameP_X29X30_STP, funcName)
    if stpMatch:
      isStp = True
    CommonUtil.logDebug("funcName=%s -> isStp=%s, stpMatch=%s", funcName, isStp, stpMatch)
    return isStp, stpMatch

  def isFuncName_LDP(funcName):
    """
    check function name is contain LDP, eg '_SPOffxxxToX29X30' or not
    eg:
      "ZdlPv_xxx_SPOff0x10ValToX29X30_0274" -> True, Match Object
    """
    isLdp = False
    ldpMatch = None
    ldpMatch = re.search(IDAUtil.funcNameP_X29X30_LDP, funcName)
    if ldpMatch:
      isLdp = True
    CommonUtil.logDebug("funcName=%s -> isLdp=%s, ldpMatch=%s", funcName, isLdp, ldpMatch)
    return isLdp, ldpMatch

  def isFuncName_STP_LDP(funcName):
    """
    check function name is 'ZdlPv_X29X30ToSPOff0xFFFFFFFFFFFFFFF0Val_SPToX29_PageAddr0xFA8000ToX8_X8Add0x760ToX8_X8Add0x8ToX1_BranchTonullsub_248_SPOff0x10ValToX29X30_0274' (which contain '_X29X30ToSPOffxxx', '_SPOffxxxToX29X30') or not
    eg:
      "ZdlPv_X29X30ToSPOff0xFFFFFFFFFFFFFFF0Val_SPToX29_PageAddr0xFA8000ToX8_X8Add0x760ToX8_X8Add0x8ToX1_BranchTonullsub_248_SPOff0x10ValToX29X30_0274" -> is match
    """
    # funcNameP_stp = re.search(IDAUtil.funcNameP_X29X30_STP, funcName)
    # isFuncName_stp = bool(funcNameP_stp)
    # funcNameP_ldp = re.search(IDAUtil.funcNameP_X29X30_LDP, funcName)
    # isFuncName_ldp = bool(funcNameP_ldp)
    isFuncName_stp, stpMatch = IDAUtil.isFuncName_STP(funcName)
    isFuncName_ldp, ldpMatch = IDAUtil.isFuncName_LDP(funcName)
    isFuncName_stp_ldp = isFuncName_stp or isFuncName_ldp
    CommonUtil.logDebug("isFuncName_stp_ldp=%s, isFuncName_stp=%s, isFuncName_ldp=%s", isFuncName_stp_ldp, isFuncName_stp, isFuncName_ldp)
    return isFuncName_stp_ldp

  def isFuncName_sub(funcName):
    """
    check is default sub_XXX function or not from name
    eg:
      sub_F332C0 -> True, "F332C0"
    """
    isSub = False
    addressStr = None
    # subMatch = re.match("^sub_[0-9A-Za-z]+$", funcName)
    subMatch = re.match("^sub_(?P<addressStr>[0-9A-Fa-f]+)$", funcName)
    # print("subMatch=%s" % subMatch)
    if subMatch:
      isSub = True
      addressStr = subMatch.group("addressStr")
    return isSub, addressStr

  def isFuncName_nullsub(funcName):
    """
    check is default nullsub_XXX function or not from name
    eg:
      nullsub_58 -> True, "58"
    """
    isNullsub = False
    suffixStr = None
    nullsubMatch = re.match("^nullsub_(?P<suffixStr>\w+)$", funcName)
    # print("nullsubMatch=%s" % nullsubMatch)
    if nullsubMatch:
      isNullsub = True
      suffixStr = nullsubMatch.group("suffixStr")
    return isNullsub, suffixStr

  def isReservedPrefix_locType(funcName):
    """
    check is reserved prefix loc_XXX / locret_XXX name or not
    eg:
      loc_100007A2C -> True, "100007A2C"
      locret_16A0 -> True, "16A0"
    """
    isLoc = False
    addressStr = None
    # locMatch = re.match("^loc_(?P<addressStr>[0-9A-Fa-f]+)$", funcName)
    locMatch = re.match("^loc(ret)?_(?P<addressStr>[0-9A-F]+)$", funcName)
    # print("locMatch=%s" % locMatch)
    if locMatch:
      isLoc = True
      addressStr = locMatch.group("addressStr")
    return isLoc, addressStr

  def isDefaultSubFunction(curAddr):
    """
    check is default sub_XXX function or not from address
    """
    isDefSubFunc = False
    curFuncName = IDAUtil.ida_getFunctionName(curAddr)
    # print("curFuncName=%s" % curFuncName)
    if curFuncName:
      isDefSubFunc, subAddStr = IDAUtil.isFuncName_sub(curFuncName)
    return isDefSubFunc, curFuncName

  def isObjcMsgSendFunction(curAddr):
    """
    check is default sub_XXX function or not from address
    """
    isObjcMsgSend = False
    curFuncName  = IDAUtil.ida_getFunctionName(curAddr)
    # print("curFuncName=%s" % curFuncName)
    if curFuncName:
      isObjcMsgSend, selectorStr = IDAUtil.isObjcMsgSendFuncName(curFuncName)
    return isObjcMsgSend, selectorStr

  def isFunc_TypeMetadataAccessorForAppDelegate(curAddr):
    """
    check is function type_metadata_accessor_for_AppDelegate or not from address
    """
    curFuncName = IDAUtil.ida_getFunctionName(curAddr)
    isTypeMetadataAccessorForAppDelegate = IDAUtil.isFuncName_TypeMetadataAccessorForAppDelegate(curFuncName)
    return isTypeMetadataAccessorForAppDelegate

  def isReg_PrologueEpilogue(regName):
    """
    Check is Prologue/Epilogue register
    eg:
      "X28" -> True
      "D8" -> True
    """
    CommonUtil.logDebug("regName=%s", regName)
    regNameUpper = regName.upper()
    CommonUtil.logDebug("regNameUpper=%s", regNameUpper)
    isPrlgEplg = regNameUpper in ARMUtil.PrologueEpilogueRegList
    CommonUtil.logDebug("isPrlgEplg=%s", isPrlgEplg)
    return isPrlgEplg

  def isOperand_PrologueEpilogue(curOperand):
    """
    Check Operand is Prologue/Epilogue or not
    eg:
      <Operand: op=X28,type=1,val=0x9D> -> True
    """
    isPrlgEplgOp = False
    opIsReg = curOperand.isReg()
    CommonUtil.logDebug("opIsReg=%s", opIsReg)
    if opIsReg:
      regName = curOperand.operand
      CommonUtil.logDebug("regName=%s", regName)
      isPrlgEplgOp = IDAUtil.isReg_PrologueEpilogue(regName)

    CommonUtil.logDebug("isPrlgEplgOp=%s", isPrlgEplgOp)
    return isPrlgEplgOp

  def isOperands_PrologueEpilogue(instOperands):
    """
    Check a instruction's all operands is Prologue/Epilogue or not
    eg:
      STP X28, X27, xxx -> True
      LDP X20, X19, xxx -> True
    """
    isAllPrlgEplg = False

    operandNum = len(instOperands)
    CommonUtil.logDebug("operandNum=%s", operandNum)
    if operandNum == 3:
      operand1 = instOperands[0]
      operand2 = instOperands[1]
      CommonUtil.logDebug("operand1=%s, operand2=%s", operand1, operand2)

      # # for debug
      # operand3 = curOperands[2]
      # print("operand3=%s" % operand3)

      op1IsPrlgEplg = IDAUtil.isOperand_PrologueEpilogue(operand1)
      op2IsPrlgEplg = IDAUtil.isOperand_PrologueEpilogue(operand2)
      CommonUtil.logDebug("op1IsPrlgEplg=%s, op2IsPrlgEplg=%s", op1IsPrlgEplg, op2IsPrlgEplg)
      isAllPrlgEplg = op1IsPrlgEplg and op2IsPrlgEplg
    
    CommonUtil.logDebug("instOperands=%s -> isAllPrlgEplg=%s", instOperands, isAllPrlgEplg)
    return isAllPrlgEplg

  def isAllPrologueStp(instructionList):
    """
    Check is all STP instruction of prologue
    eg:
      STP X28, X27, [SP,#arg_70]
    """
    isAllPrlgStp = True
    for eachInst in instructionList:
      CommonUtil.logDebug("eachInst=%s", eachInst)
      isStp = eachInst.isStp()
      if isStp:
        # check operand register match or not
        curOperands = eachInst.operands
        CommonUtil.logDebug("curOperands=%s", curOperands)
        isOperandsPrlgStp = IDAUtil.isOperands_PrologueEpilogue(curOperands)
        CommonUtil.logDebug("isOperandsPrlgStp=%s", isOperandsPrlgStp)
        if isOperandsPrlgStp:
          isAllPrlgStp = isOperandsPrlgStp
        else:
          isAllPrlgStp = False
          break
      else:
        isAllPrlgStp = False
        break

    CommonUtil.logDebug("isAllPrlgStp=%s", isAllPrlgStp)
    return isAllPrlgStp

  def isInstruction_Prologue(curInstruction):
    """
    Check whether instruction is prologue(STP)
    eg:
      STP X29, X30, [SP,#0x10+var_s0] -> True
      STP X28, X27, [SP,#arg_70] -> True
      STP X20, X19, [SP,#-0x10+var_10]! -> True
    """
    isInstPrlg = False
    isStp = curInstruction.isStp()
    if isStp:
      isOperandsPrlgStp = IDAUtil.isOperands_PrologueEpilogue(curInstruction.operands)
      isInstPrlg = isStp and isOperandsPrlgStp
    CommonUtil.logDebug("curInstruction=%s -> isInstPrlg=%s", curInstruction, isInstPrlg)
    return isInstPrlg

  def isInstruction_Epilogue(curInstruction):
    """
    Check whether instruction is epilogue(LDP)
    eg:
      LDP X20, X19, [SP+0x10+var_10],#0x20 -> True
    """
    isInstEplg = False
    isLdp = curInstruction.isLdp()
    if isLdp:
      isOperandsPrlgStp = IDAUtil.isOperands_PrologueEpilogue(curInstruction.operands)
      isInstEplg = isLdp and isOperandsPrlgStp
    CommonUtil.logDebug("curInstruction=%s -> isInstEplg=%s", curInstruction, isInstEplg)
    return isInstEplg

  def removePrologueEpilogueInstructions(instructionList):
    """
    remove prologue and epilogue instructions
    """
    CommonUtil.logDebug("input: instructionList=%s", Instruction.listToStr(instructionList))
    isContinueCheck = True
    while isContinueCheck and instructionList:
      isPrlgEplg = False

      firstInst = instructionList[0]
      CommonUtil.logDebug("firstInst=%s", firstInst)
      firstIsPrlg = IDAUtil.isInstruction_Prologue(firstInst)
      CommonUtil.logDebug("firstIsPrlg=%s", firstIsPrlg)
      if firstIsPrlg:
        isPrlgEplg = True
        instructionList.pop(0)
      
      if instructionList:
        lastInst = instructionList[-1]
        CommonUtil.logDebug("lastInst=%s", lastInst)
        lastIsEplg = IDAUtil.isInstruction_Epilogue(lastInst)
        CommonUtil.logDebug("lastIsEplg=%s", lastIsEplg)
        if lastIsEplg:
          isPrlgEplg = True
          instructionList.pop(-1)

      CommonUtil.logDebug("current loop end: instructionList=%s", Instruction.listToStr(instructionList))

      if not isPrlgEplg:
        isContinueCheck = False

    CommonUtil.logDebug("output: instructionList=%s", Instruction.listToStr(instructionList))
    return instructionList

  def isRenamedFunctionName(funcName):
    """
    check is has renamed function name or not
    eg:
      "getMap_recordNumber_SFI_recordValue_B6400" -> True,"B6400"
      "_objc_msgSend$_fileNameUrlForProvider_fileName_withExtension_private__DD20" -> True,"_DD20"
      "_objc_msgSend$_fileWriteOptions" -> False,""
    """
    isRenamed = False
    addrSuffix = ""

    isSubFunc, addressStr = IDAUtil.isFuncName_sub(funcName)
    print("isSubFunc=%s, addressStr=%s" % (isSubFunc, addressStr))

    if not isSubFunc:
      addrSuffixMatch = re.search(".+(?P<addrSuffix>_[A-Z0-9]{4,20})$", funcName)
      # print("addrSuffixMatch=%s" % addrSuffixMatch)
      isRenamed = bool(addrSuffixMatch)
      # print("isRenamed=%s" % isRenamed)
      if addrSuffixMatch:
        addrSuffix = addrSuffixMatch.group("addrSuffix")
        # print("addrSuffix=%s" % addrSuffix)

    return isRenamed, addrSuffix

  def removeFuncNameAddressSuffixIfExist(funcName):
    """
    remove address suffix if exist
    eg:
      "_objc_msgSend$initWithKeyValueStore:namespace:error:_D280" -> "_objc_msgSend$initWithKeyValueStore:namespace:error:"
      "objc_msgSend$copyItemAtPath_toPath_error_X22toX0_X24toX2_X25toX3_EFB4" -> "objc_msgSend$copyItemAtPath_toPath_error_X22toX0_X24toX2_X25toX3"
    """
    funcNameNoAddrSuffix = re.sub("_[A-Z0-9]{4,20}$", "", funcName)
    # print("funcName=%s -> funcNameNoAddrSuffix=%s" % (funcName, funcNameNoAddrSuffix))
    return funcNameNoAddrSuffix
