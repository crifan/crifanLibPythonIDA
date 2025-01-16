# Function: Common util functions in IDA Python Plugin
#   mainly copy from https://github.com/crifan/crifanLibPython/tree/master/python3/crifanLib
# Author: Crifan Li

import logging
import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
# import time
import codecs
import json

logUsePrint = True
logUseLogging = False
# logUsePrint = False
# logUseLogging = True # Note: current will 1 log output 7 log -> maybe IDA bug, so temp not using logging

logLevel = logging.INFO
# logLevel = logging.DEBUG # for debug


# Update: 20250115
# Link: https://github.com/crifan/crifanLibPythonIDA/blob/main/CommonUtil.py
class CommonUtil:

  CURRENT_LIB_FILENAME = "crifanLogging"

  LOG_FORMAT_FILE = "%(asctime)s %(filename)s:%(lineno)-4d %(levelname)-7s %(message)s"
  # https://docs.python.org/3/library/time.html#time.strftime
  LOG_FORMAT_FILE_DATETIME = "%Y/%m/%d %H:%M:%S"
  LOG_LEVEL_FILE = logging.DEBUG
  LOG_FORMAT_CONSOLE = "%(asctime)s %(filename)s:%(lineno)-4d %(levelname)-7s %(message)s"
  LOG_FORMAT_CONSOLE_DATETIME = "%Y%m%d %H:%M:%S"
  LOG_LEVEL_CONSOLE = logging.INFO
  # LOG_LEVEL_CONSOLE = logging.DEBUG

  def loggingInit(filename = None,
                  fileLogLevel = LOG_LEVEL_FILE,
                  fileLogFormat = LOG_FORMAT_FILE,
                  fileLogDateFormat = LOG_FORMAT_FILE_DATETIME,
                  enableConsole = True,
                  consoleLogLevel = LOG_LEVEL_CONSOLE,
                  consoleLogFormat = LOG_FORMAT_CONSOLE,
                  consoleLogDateFormat = LOG_FORMAT_CONSOLE_DATETIME,
                  ):
      """
      init logging for both log to file and console

      :param filename: input log file name
          if not passed, use current lib filename
      :return: none
      """
      logFilename = ""
      if filename:
          logFilename = filename
      else:
          # logFilename = __file__ + ".log"
          # '/Users/crifan/dev/dev_root/xxx/crifanLogging.py.log'
          logFilename = CommonUtil.CURRENT_LIB_FILENAME + ".log"

      # logging.basicConfig(
      #                 level    = fileLogLevel,
      #                 format   = fileLogFormat,
      #                 datefmt  = fileLogDateFormat,
      #                 filename = logFilename,
      #                 encoding = "utf-8",
      #                 filemode = 'w')

      # rootLogger = logging.getLogger()
      rootLogger = logging.getLogger("")
      rootLogger.setLevel(fileLogLevel)
      fileHandler = logging.FileHandler(
          filename=logFilename,
          mode='w',
          encoding="utf-8")
      fileHandler.setLevel(fileLogLevel)
      fileFormatter = logging.Formatter(
          fmt=fileLogFormat,
          datefmt=fileLogDateFormat
      )
      fileHandler.setFormatter(fileFormatter)
      rootLogger.addHandler(fileHandler)

      if enableConsole :
          # define a Handler which writes INFO messages or higher to the sys.stderr
          console = logging.StreamHandler()
          console.setLevel(consoleLogLevel)
          # set a format which is simpler for console use
          consoleFormatter = logging.Formatter(
              fmt=consoleLogFormat,
              datefmt=consoleLogDateFormat)
          # tell the handler to use this format
          console.setFormatter(consoleFormatter)
          rootLogger.addHandler(console)

  def log_print(formatStr, *paraTuple):
    if paraTuple:
      print(formatStr % paraTuple)
    else:
      print(formatStr)

  def logInfo(formatStr, *paraTuple):
    if logUsePrint:
      if logLevel <= logging.INFO:
        CommonUtil.log_print(formatStr, *paraTuple)

    if logUseLogging:
      logging.info(formatStr, *paraTuple)

  def logDebug(formatStr, *paraTuple):
    if logUsePrint:
      if logLevel <= logging.DEBUG:
        CommonUtil.log_print(formatStr, *paraTuple)
    
    if logUseLogging:
      logging.debug(formatStr, *paraTuple)

  def logMainStr(mainStr):
    mainDelimiter = "="*40
    # print("%s %s %s" % (mainDelimiter, mainStr, mainDelimiter))
    CommonUtil.logInfo("%s %s %s", mainDelimiter, mainStr, mainDelimiter)

  def logSubStr(subStr):
    subDelimiter = "-"*30
    # print("%s %s %s" % (subDelimiter, subStr, subDelimiter))
    CommonUtil.logDebug("%s %s %s", subDelimiter, subStr, subDelimiter)
    # CommonUtil.logInfo("%s %s %s", subDelimiter, subStr, subDelimiter)

  def logSubSubStr(subStr):
    subsubDelimiter = "-"*20
    # print("%s %s %s" % (subsubDelimiter, subStr, subsubDelimiter))
    CommonUtil.logDebug("%s %s %s", subsubDelimiter, subStr, subsubDelimiter)
    # CommonUtil.logInfo("%s %s %s", subsubDelimiter, subStr, subsubDelimiter)

  def datetimeToStr(inputDatetime, format="%Y%m%d_%H%M%S"):
      """Convert datetime to string

      Args:
          inputDatetime (datetime): datetime value
      Returns:
          str
      Raises:
      Examples:
          datetime.datetime(2020, 4, 21, 15, 44, 13, 2000) -> '20200421_154413'
      """
      datetimeStr = inputDatetime.strftime(format=format)
      # print("inputDatetime=%s -> datetimeStr=%s" % (inputDatetime, datetimeStr)) # 2020-04-21 15:08:59.787623
      return datetimeStr

  def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
      """
      get current datetime then format to string

      eg:
          20171111_220722

      :param outputFormat: datetime output format
      :return: current datetime formatted string
      """
      curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
      # curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
      curDatetimeStr = CommonUtil.datetimeToStr(curDatetime, format=outputFormat)
      return curDatetimeStr

  def loadTextFromFile(fullFilename, fileEncoding="utf-8"):
    """load file text content from file"""
    with codecs.open(fullFilename, 'r', encoding=fileEncoding) as fp:
      allText = fp.read()
      # logging.debug("Complete load text from %s", fullFilename)
      return allText

  def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
      """
          save json dict into file
          for non-ascii string, output encoded string, without \\u xxxx
      """
      with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
          json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)
          # logging.debug("Complete save json %s", fullFilename)

  def listSubfolderFiles(subfolder, isIncludeFolder=True, isRecursive=False):
    """os.listdir recursively

    Args:
        subfolder (str): sub folder path
        isIncludeFolder (bool): whether is include folder. Default is True. If True, result contain folder
        isRecursive (bool): whether is recursive, means contain sub folder. Default is False
    Returns:
        list of str
    Raises:
    """
    allSubItemList = []
    curSubItemList = os.listdir(path=subfolder)
    print("len(curSubItemList)=%d, curSubItemList=%s" % (len(curSubItemList), curSubItemList))
    for curSubItem in curSubItemList:
      print("curSubItem=%s" % curSubItem)
      curSubItemFullPath = os.path.join(subfolder, curSubItem)
      print("curSubItemFullPath=%s" % curSubItemFullPath)
      if os.path.isfile(curSubItemFullPath):
        print("is file for: %s" % curSubItemFullPath)
        allSubItemList.append(curSubItemFullPath)
      else:
        print("NOT file for: %s" % curSubItemFullPath)
        if isIncludeFolder:
          if os.path.isdir(curSubItemFullPath):
            subSubItemList = CommonUtil.listSubfolderFiles(curSubItemFullPath, isIncludeFolder, isRecursive)
            allSubItemList.extend(subSubItemList)

    if isIncludeFolder:
      allSubItemList.append(subfolder)

    return allSubItemList

  def createFolder(folderFullPath):
    """
      create folder, even if already existed
      Note: for Python 3.2+
    """
    os.makedirs(folderFullPath, exist_ok=True)
