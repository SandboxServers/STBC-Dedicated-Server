if __name__ == "__main__":
	import TimingGraph
	TimingGraph.Go()
	import sys
	sys.exit()

from Tkinter import *
from tkSimpleDialog import *
from tkFileDialog import *

import Pmw
import string
import os
import re

g_iFirstFrame = None
g_iLastFrame = None
g_pGraphWindow = None

def GrabDataAndTitle(sLine):
	# Find the last " - " in the string.  That's the separator between
	# the description and the timing data.
	iIndex = string.rfind(sLine, " - ")
	sTitle = sLine[:iIndex]

	iIndex = iIndex + 3
	iLineLength = len(sLine)

	#sTitle, sData = string.split(sLine, " - ", 1)
	print "Reading %s" % (sTitle)

	lData = []

	# This way of splitting the data is marginally slower
	# than the big while loop below.  I blame memory allocation and copying.
## 	def AddData(sNumber, lData = lData):
## 		sFrame, sValue = string.split(sNumber, ":", 1)
## 		lData.append( (float(sValue), int(sFrame)) )
## 	map(AddData, string.split( string.strip(sLine[iIndex:]), " " ))

	iCount = 0
	while iIndex < iLineLength:
		# Grab the next number..  First strip any spaces.
		while (iIndex < iLineLength) and (sLine[iIndex] in " \n"):
			iIndex = iIndex + 1

		if iIndex >= iLineLength:
			break

		# Found the start of a number.  Look for the end.
		iEnd = iIndex + 1
		while (iEnd < iLineLength) and (sLine[iEnd] not in " \n"):
			iEnd = iEnd + 1

		sNumber = sLine[iIndex:iEnd]
		if sNumber:#  and  (sNumber != "\n"):
			iCount = iCount + 1
			if (iCount % 5000) == 0:
				print "Reading %s (position %d/%d)" % (sTitle, iIndex, iLineLength)

			# Found the end of the number.  Get the value.
			try:
				sFrame, sValue, sSeqStart, sSeqEnd = string.split(sNumber, ":")
			except ValueError:
				print "Error unpacking number from:\n" + sNumber
				raise

			#try:
			lDataElement = (float(sValue), int(sFrame), int(sSeqStart), int(sSeqEnd))
			lData.append(lDataElement)
			#except:
			#	break

		iIndex = iEnd + 1

	# First frame will be in the first entry, last frame will be in the last entry...
	# Check if we need to update the global first/last settings.
	global g_iFirstFrame, g_iLastFrame
	try:
		if (g_iFirstFrame is None)  or  (lData[0][1] < g_iFirstFrame):
			g_iFirstFrame = lData[0][1]
		if (g_iLastFrame is None)  or  (lData[len(lData) - 1][1] > g_iLastFrame):
			g_iLastFrame = lData[len(lData) - 1][1]
	except IndexError: pass

	return (lData, sTitle)

def ShowGraph(dData, sTitle):
	global g_pGraphWindow

	# Remove the min/max extremes...
	lGraphData = RemoveMinMax( TrimStartEnd(dData[sTitle]) )

	try:
		g_pGraphWindow.winfo_children()
	except:
		g_pGraphWindow = None

	if not g_pGraphWindow:
		g_pGraphWindow = Toplevel()
		iScreenWidth = g_pGraphWindow.winfo_screenwidth()
		iScreenHeight = g_pGraphWindow.winfo_screenheight()
		g_pGraphWindow.geometry("%dx%d+%d+%d" % (iScreenWidth * 0.95, iScreenHeight * 0.9, iScreenWidth * 0.025, iScreenHeight * 0.025))
		g_pGraphWindow.title("Graph of %s (Right-click to close, left click on any point to Search Frames on that frame" % sTitle)

		pGraph = Graph(g_pGraphWindow)
		pGraph.pack(fill=BOTH, expand=YES)
	else:
		pGraph = g_pGraphWindow.winfo_children()[0]

	pGraph.AddData(sTitle, lGraphData, dData)
	#pGraph.AddData("Frame time", dData["Frame time"], dData)
	pGraph.update()
	pGraph.DrawGraph()

def TimesOnly(lData):
	lTimes = []
	for fTime, iFrame in lData:
		lTimes.append(fTime)
	return lTimes

def RemoveMinMax(lData):
	global iRemoveCount
	if iRemoveCount == 0:
		return lData[:]

	lTempCopy = lData[:]
	lTempCopy.sort()

	lFixedData = lData[:]
	for iIndex in range( iRemoveCount.get() ):
		try:
			try:
				lFixedData.remove( lTempCopy[iIndex] )
				lFixedData.remove( lTempCopy[ len(lTempCopy) - iIndex - 1 ] )
			except ValueError:
				lFixedData = []
				break
				#print "Failed to remove item " + str(len(lTempCopy) - iIndex - 1) + " in " + str(lTempCopy) + " from " + str(lFixedData)
		except IndexError:
			# Tried to remove too many min/maxes.
			#print "Tried to remove too many min/max extremes.  Displaying"
			#print "normal graph."
			lFixedData = []
			break

	return lFixedData

def TrimStartEnd(lData, iStart = None, iEnd = None):
	if iStart is None:
		iStart = iStartFrame.get()
	if iEnd is None:
		iEnd = iEndFrame.get()

	if (iStart == g_iFirstFrame)  and  (iEnd == g_iLastFrame):
		return lData

	lFixedData = lData[:]
	for lDatum in lData:
		if (lDatum[1] < iStart)  or  (lDatum[1] > iEnd):
			lFixedData.remove(lDatum)

	return lFixedData

def Go(sLineToGraph = "GameLoop"):
	root = Tk()

	AddFirstLastFrameScales(root)

	pMainFrame = Pmw.ScrolledFrame(root)
	pMainFrame.pack(fill=BOTH, expand=YES, side=BOTTOM)

	root.after_idle(lambda pRoot = root, pMainFrame=pMainFrame : ContinueLoading(pRoot, pMainFrame))
	#ContinueLoading(pFrame,pMainFrame)

	root.mainloop()

def AddFirstLastFrameScales(root):
	# Add a field for changing the first/last frames to display.
	pFrame = Frame(root)
	pFrame.pack(side=TOP, fill=X)
	
	global iStartFrame
	iStartFrame = IntVar()
	iStartFrame.set(0)

	global iEndFrame
	iEndFrame = IntVar()
	iEndFrame.set(1)

	Label(pFrame, text="Starting frame:").pack(side=LEFT)

	global pStartScale
	pStartScale = Scale(pFrame, variable=iStartFrame, from_=0, to=1, orient=HORIZONTAL, command=StartEndFrameChanged)
	pStartScale.pack(side=LEFT, fill=X, expand=YES)

	Label(pFrame, text="Ending frame:").pack(side=LEFT)

	global pEndScale
	pEndScale = Scale(pFrame, variable=iEndFrame, from_=0, to=1, orient=HORIZONTAL, command=StartEndFrameChanged)
	pEndScale.pack(side=LEFT, fill=X, expand=YES)

def StartEndFrameChanged(ignored):
	iStart = iStartFrame.get()
	iEnd = iEndFrame.get()

	pStartScale["to"] = iEnd
	pEndScale["from_"] = iStart

def UpdateFirstLastFrame():
	global g_iFirstFrame, g_iLastFrame
	if g_iFirstFrame is None:
		g_iFirstFrame = 0
	if g_iLastFrame is None:
		g_iLastFrame = 1

	pStartScale["from_"] = g_iFirstFrame
	pStartScale["to"] = g_iLastFrame

	pEndScale["from_"] = g_iFirstFrame
	pEndScale["to"] = g_iLastFrame

	iStartFrame.set(g_iFirstFrame)
	iEndFrame.set(g_iLastFrame)

def ContinueLoading(pRoot, pMainFrame):
	sFile = GetFilename()
	#askstring("Filename", "Enter name of the profiling data file (leave blank for RawTiming.txt):")
	print "File is: " + str(sFile)
	if not sFile:
		pRoot.destroy()
		return
	file = open(sFile, "r")

	# Log all the function titles and the data we have.
	print "Reading file..."

	pRoot.title("Profiling data from %s" % sFile)

	print "Processing entries..."
	dData = {}
	lTitles = []
	while 1:
		sLine = file.readline()
		if not sLine:
			break

		lData, sTitle = GrabDataAndTitle( sLine )
		lTitles.append(sTitle)
		dData[sTitle] = lData

	file.close()

	print "Fixing event type numbers.."
	FixEventTypeNumbers(dData, lTitles)

	print "Sorting titles..."
	lTitles.sort()

	# Add a field for changing the number of min/max extremes
	# that are removed.

	UpdateFirstLastFrame()

	lButtonFrames = ( Frame(pRoot), Frame(pRoot) )
	lButtonFrames[0].pack(side=TOP, fill=X)
	lButtonFrames[1].pack(side=TOP, fill=X)

	Label(lButtonFrames[0], text="Number of min/max pairs to remove:").pack(side=LEFT)
	global iRemoveCount
	iRemoveCount = IntVar()
	iRemoveCount.set(0)
	Scale(lButtonFrames[0], variable=iRemoveCount, from_=0, to=20, orient=HORIZONTAL).pack(side=LEFT)

	# A button to remove python entries..
	#Button(lButtonFrames[0], text="Reload (debugging)", command=Reload).pack(side=LEFT)
	Button(lButtonFrames[0], text="Search Frames", command = lambda lTitles=lTitles, dData = dData, pParent = pRoot : SearchFrames(lTitles, dData, pParent)).pack(side=LEFT)
	Button(lButtonFrames[0], text="Remove Python", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior() : RemovePython(lTitles, dData, pParent)).pack(side=LEFT)
	Button(lButtonFrames[0], text="Remove Useless", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior() : RemoveUseless(lTitles, dData, pParent)).pack(side=LEFT)

	global g_iMergeSameFrame
	g_iMergeSameFrame = IntVar()
	Checkbutton(lButtonFrames[1], text="Always merge samples on same frame", variable=g_iMergeSameFrame).pack(side=LEFT)
	Button(lButtonFrames[1], text="Sort by Mean", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior(), pFunc = FindMean : SortByData(lTitles, dData, pParent, pFunc)).pack(side=LEFT)
	Button(lButtonFrames[1], text="Sort by Max", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior(), pFunc = FindMax : SortByData(lTitles, dData, pParent, pFunc)).pack(side=LEFT)
	Button(lButtonFrames[1], text="Sort by Num Samples", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior(), pFunc = len : SortByData(lTitles, dData, pParent, pFunc)).pack(side=LEFT)
	Button(lButtonFrames[1], text="Sort by total time", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior(), pFunc = FindTotalTime : SortByData(lTitles, dData, pParent, pFunc)).pack(side=LEFT)
	Button(lButtonFrames[1], text="Sort by Title", command = lambda lTitles=lTitles, dData = dData, pParent = pMainFrame.interior() : SortByTitle(lTitles, dData, pParent)).pack(side=LEFT)



	RebuildButtons(lTitles, dData, pMainFrame.interior())


def Reload():
	pMod = __import__(__name__)
	reload(pMod)

def FixEventTypeNumbers(dData, lTitles):
	try:
		eventfile = open("../EventTypes.txt", "rt")
	except:
		return

	dEventTypes = {}
	for sLine in eventfile.readlines():
		sName, sNum = string.split(sLine, " = ")
		dEventTypes[int(sNum)] = sName
	del eventfile

	for sKey in dData.keys():
		sEventMatch = "ProcessSingleEvent, Type "
		if sKey[:len(sEventMatch)] == sEventMatch:
			iType = int( sKey[len(sEventMatch):] )
			try:
				sType = dEventTypes[iType]
			except:
				continue

			dData[sEventMatch + sType] = dData[sKey]
			del dData[sKey]

			lTitles.remove(sKey)
			lTitles.append(sEventMatch + sType)

def RebuildButtons(lTitles, dData, pParent):
	for pChild in pParent.winfo_children():
		pChild.destroy()

	pFrame = None
	for iNum in range( len(lTitles) ):
		if iNum % 28 == 0  or  (pFrame == None):
			pFrame = Frame(pParent)
			pFrame.pack(side=LEFT, fill=Y)

		sTitle = lTitles[iNum]
		pCommandFunc = lambda func=ShowGraph, dData=dData, sTitle=sTitle: func(dData, sTitle)
		Button(pFrame, text=lTitles[iNum], command=pCommandFunc).pack(side=TOP)

def SearchFrames(lTitles, dData, pParent, iSelectedFrame = None):
	# Create a "loading" dialog box..
	pLoading = Toplevel(pParent)
	pLoading.title("Loading...")
	pLoading.focus_set()
	Label(pLoading, text="Processing \"Search Frames\" data...", font=("Verdana", 18)).pack()
	pLoading.update()

	# Create a new window to search through frame-by-frame information.
	pTop = Toplevel(pParent)
	pTop.title("Search Frames")
	# Get rid of the "loading" dialog box when this is done being setup.
	pTop.after_idle(pLoading.destroy)

	# Index things by frame number...
	lFrameData = (lTitles, dData)

	iMinFrame = iStartFrame.get()
	iMaxFrame = iEndFrame.get()

	pInfoFrame = Pmw.ScrolledFrame(pTop)
	pInfoFrame.pack(fill=BOTH, expand=YES, side=BOTTOM)

	pSelectFrame = Frame(pTop)
	pSelectFrame.pack(side=TOP, fill=X) #, expand=YES)
	Label(pSelectFrame, text="Choose frame:").pack(side=LEFT)
	global iFrameNum
	iFrameNum = IntVar()
	if iSelectedFrame is not None:
		iFrameNum.set(iSelectedFrame)
	else:
		iFrameNum.set(iMinFrame)

	Scale(pSelectFrame, variable=iFrameNum, from_=iMinFrame, to=iMaxFrame, orient=HORIZONTAL, command=lambda something, lFrameData=lFrameData, pInfoFrame=pInfoFrame.interior() : FrameChanged(lFrameData, pInfoFrame)).pack(side=LEFT, fill=X, expand=YES)

	# Various buttons.
	pButtonFrame = Frame(pTop)
	pButtonFrame.pack(side=TOP, fill=X)

	Button(pButtonFrame, text="Sort by Name", command=lambda pSort = None, lFrameData = lFrameData, pInfoFrame = pInfoFrame.interior(): ChangeFrameSorting(pSort, lFrameData, pInfoFrame)).pack(side=LEFT)
	Button(pButtonFrame, text="Sort by Time", command=lambda pSort = SortFrameByTime, lFrameData = lFrameData, pInfoFrame = pInfoFrame.interior(): ChangeFrameSorting(pSort, lFrameData, pInfoFrame)).pack(side=LEFT)
	Button(pButtonFrame, text="Show Call Graph", command=lambda lFrameData = lFrameData, pInfoFrame = pInfoFrame.interior(): ShowCallGraph(lFrameData, pInfoFrame)).pack(side=LEFT)

	global g_pFrameSortFunc
	g_pFrameSortFunc = None

def ChangeFrameSorting(pSortFunc, lFrameData, pInfoFrame):
	global g_pFrameSortFunc
	g_pFrameSortFunc = pSortFunc
	FrameChanged(lFrameData, pInfoFrame)

def SortFrameByTime(lValue1, lValue2):
	return cmp(lValue2[1], lValue1[1])

def FrameChanged(lFrameData, pInfoFrame):
	# Find which data elements are in this frame.
	lDataInFrame, lFrameTime = GetDataInFrame(lFrameData, iFrameNum.get(), lambda x: x[0])

	# Sort lDataInFrame.
	if(g_pFrameSortFunc):
		lDataInFrame.sort(g_pFrameSortFunc)
	else:
		lDataInFrame.sort()

	if lFrameTime:
		lDataInFrame = lFrameTime + lDataInFrame

	for pChild in pInfoFrame.winfo_children():
		pChild.destroy()

	for sTitle, fTime in lDataInFrame:
		Label(pInfoFrame, text="%s: %f" % (sTitle, fTime)).pack(side=TOP, anchor=W)

def GetDataInFrame(lFrameData, iFrame, pFilter):
	lTitles, dData = lFrameData
	lDataInFrame = []
	lFrameTime = []

	for sTitle in lTitles:
		# Binary search for the relevant frame..
		lData = dData[sTitle]
		iMin = 0
		iMax = len(lData)
		if iMax == 0:
			continue
		while iMin < iMax:
			iCurrent = (iMax + iMin) / 2
			if lData[iCurrent][1] > iFrame:
				# Too great.  Search lower.
				iMax = iCurrent
			elif lData[iCurrent][1] < iFrame:
				# Too low.  Search higher.
				iMin = iCurrent + 1
			else:
				# We're in the middle of the desired frame.  Scroll down
				# to the beginning of this frame.
				while (iCurrent > 0)  and  (lData[iCurrent - 1][1] == iFrame):
					iCurrent = iCurrent - 1
				break

		while lData[iCurrent][1] == iFrame:
			# Found data in this frame.  Yaaay.  Save it.
			#print "Found data: ", sTitle, lData[iCurrent]
			if sTitle == "Frame time":
				lFrameTime.append( (sTitle, pFilter(lData[iCurrent])) )
			else:
				lDataInFrame.append( (sTitle, pFilter(lData[iCurrent])) )
			iCurrent = iCurrent + 1
			if iCurrent >= len(lData):
				break

	return (lDataInFrame, lFrameTime)

def ShowCallGraph(lFrameData, pInfoFrame):
	# Find which data elements are in this frame.
	lDataInFrame, lFrameTime = GetDataInFrame(lFrameData, iFrameNum.get(), lambda x: x)

	# Clear out the existing display...
	for pChild in pInfoFrame.winfo_children():
		pChild.destroy()

	# Show the frame time...
	for sTitle, lData in lFrameTime:
		Label(pInfoFrame, text="%s: %f" % (sTitle, lData[0])).pack(side=TOP, anchor=W)

	# Display the rest of the data, as a call graph...
	# First, find the next sequence number...
	lContainingStack = []
	while lDataInFrame:
		# Find the lowest and highest remaining sequence numbers...
		iLowestSeq = 32768 * 32768
		iLowestIndex = -1
		for iIndex in range(len( lDataInFrame )):
			sTitle, lData = lDataInFrame[iIndex]
			if lData[2] < iLowestSeq:
				iLowestSeq = lData[2]
				iLowestIndex = iIndex

		# Find the depth for the item with the lowest sequence number.
		sTitle, lData = lDataInFrame[iLowestIndex]
		iSeqStart = lData[2]
		iSeqEnd = lData[3]

		iDepth = len(lContainingStack)
		while iDepth > 0:
			# If we're between the sequence start/end at this level
			# of the stack, this is our depth.
			iStart, iEnd = lContainingStack[iDepth - 1]
			if iSeqStart > iStart  and  iSeqEnd < iEnd:
				# This is where we go...
				break
			else:
				# We're not at this depth.  Move up one.
				lContainingStack.pop()
				iDepth = iDepth - 1

		# Add ourselves to the stack...
		lContainingStack.append( (iSeqStart, iSeqEnd) )

		# Display our label, indented by our current depth.
		#Label(pInfoFrame, text="%s[%d-%d]%s: %f" % (" -" * iDepth, lData[2], lData[3], sTitle, lData[0])).pack(side=TOP, anchor=W)  # Debugging.
		Label(pInfoFrame, text="%s%s: %f" % (" -" * iDepth, sTitle, lData[0])).pack(side=TOP, anchor=W)

		# Remove ourselves from the list of possible things to display.
		lDataInFrame.pop(iLowestIndex)

def RemovePython(lTitles, dData, pParent):
	pPythonMatch = re.compile("^Run(Function|Method):")
	iIndex = len(lTitles) - 1
	while iIndex >= 0:
		sTitle = lTitles[iIndex]
		if pPythonMatch.match(sTitle):
			print "Removing " + sTitle
			lTitles.remove(sTitle)
		iIndex = iIndex - 1

	RebuildButtons(lTitles, dData, pParent)

def RemoveUseless(lTitles, dData, pParent):
	iIndex = len(lTitles) - 1
	while iIndex >= 0:
		sTitle = lTitles[iIndex]
		if len(dData[sTitle]) < 2:
			lTitles.remove(sTitle)
		iIndex = iIndex - 1

	RebuildButtons(lTitles, dData, pParent)

def SortByTitle(lTitles, dData, pParent):
	lTitles.sort()
	RebuildButtons(lTitles, dData, pParent)

def SortByData(lTitles, dData, pParent, pFunc):
	# Re-sort the list again, so the entries are
	# sorted by mean value.  In order to do this,
	# first prefix each entry by its mean...
	for iIndex in range( len( lTitles ) ):
		sTitle = lTitles[iIndex]
		# Find this item's mean.
		fMean = pFunc( RemoveMinMax(dData[sTitle]) )
		# Prefix this entry with its mean...
		lTitles[iIndex] = (fMean, sTitle)

	lTitles.sort()
	lTitles.reverse()
	
	# Then go through and remove those means, so the
	# titles don't look messed up.
	for iIndex in range( len( lTitles ) ):
		lTitles[iIndex] = lTitles[iIndex][1]

	RebuildButtons(lTitles, dData, pParent)

def FindMean(lData):
	if lData:
		fTotal = 0.0
		for fTime, iFrame in lData:
			fTotal = fTotal + fTime

		return fTotal / len(lData)
	return 0.0

def FindMax(lData):
	fMax = 0.0
	for fTime, iFrame in lData:
		if fTime > fMax:
			fMax = fTime
	return fMax

def FindTotalTime(lData):
	fTotalTime = 0.0
	for fTime, iFrame in lData:
		fTotalTime = fTotalTime + fTime
	return fTotalTime

def GetFilename():
	import Tkinter
	parent = Tkinter._default_root

	# Find the default filename..  It's the most recent RawTiming*.txt
	# in our parent directory.
	pTimingMatch = re.compile(r"RawTiming(\d*)\.txt")
	sDefaultFile = None
	iHighestNum = -1
	for sFile in os.listdir("../"):
		pMatch = pTimingMatch.match(sFile)
		if pMatch:
			if not sDefaultFile:
				sDefaultFile = sFile
			else:
				sNumbers = pMatch.group(1)
				if sNumbers:
					iNum = int(sNumbers)
					if iNum > iHighestNum:
						iHighestNum = iNum
						sDefaultFile = sFile

	return askopenfilename(initialdir="../", initialfile=sDefaultFile, title="Open Profiling Information File")

class Graph(Frame):
	def __init__(self, pRoot, **dOptions):
		apply(Frame.__init__, (self, pRoot), dOptions)

		# Controls go along the top.
		self.pTopFrame = Frame(self, height=40)
		self.pTopFrame.pack(side=TOP, fill=X)

		Button(self.pTopFrame, text="Merge samples on\nsame frame", command=self.MergeSameFrameSamples).pack(side=LEFT)

		# Graph display goes along the bottom.
		pBottomFrame = Frame(self)
		pBottomFrame.pack(side=BOTTOM, fill=BOTH, expand=YES)

		pGraphFrame = Frame(pBottomFrame)
		pGraphFrame.pack(side=RIGHT, fill=BOTH, expand=YES)

		self.pCanvas = Canvas(pGraphFrame, background="black", relief="sunken")
		self.pCanvas.pack(side=RIGHT, fill=BOTH, expand=YES)

		self.pLeftTicks = Canvas(pGraphFrame, width=20)
		self.pLeftTicks.pack(side=LEFT, anchor=SE, fill=Y)

		self.pTextFrame = Frame(pBottomFrame, width=40)
		self.pTextFrame.pack(side=LEFT, fill=Y)

		self.fScale = 1.0
		self.fXOffset = 0.0
		self.bDrawn = 0
		self.fArtificialYMax = None

		self.lColors = ( "white", "red", "blue", "green", "orange", "yellow", "purple", "gray", "brown", "pink" )
		self.lTitles = []
		self.llData = []

		self.bind("<Configure>", self.Resize)
		self.pCanvas.bind("<Button-1>", self.LeftClick)
		pRoot.bind("<Button-3>", lambda event, pRoot=pRoot: pRoot.destroy())

	def AddData(self, sTitle, lData, dAllData):
		if not lData:
			from tkMessageBox import showerror
			showerror("No data", "No data in %s" % (sTitle))
			return

		self.lTitles.append(sTitle)
		self.llData.append(lData)
		self.dAllData = dAllData

		fMin, fMax, fTotal = (1.0e20, -1.0e20, 0.0)
		for fTime, iFrame, iStartSeq, iEndSeq in lData:
			fMin = min(fTime, fMin)
			fMax = max(fTime, fMax)
			fTotal = fTotal + fTime

		sColor = self.lColors[(len(self.lTitles) - 1) % len(self.lColors)]
		pLabel = Label(self.pTopFrame, text="(%s)\n(Min:%f, Max:%f, Avg:%f)" % (sTitle, fMin, fMax, fTotal / len(lData)), foreground = sColor)
		pLabel.pack(side=LEFT)

		if g_iMergeSameFrame.get():
			# All graphed data should have samples on the same frame merged (summed) to
			# a single sample.
			self.MergeData(lData)

	def MergeSameFrameSamples(self):
		for lData in self.llData:
			self.MergeData(lData)

		self.DrawGraph()

	def MergeData(self, lData):
		iLastFrame = -1
		iDatum = 0
		while iDatum < len(lData):
			fTime, iFrame, iSeqStart, iSeqEnd = lData[iDatum]

			if iFrame == iLastFrame:
				# Merge with data from the last frame.
				lData[iDatum - 1] = list(lData[iDatum - 1])
				pLast = lData[iDatum - 1]
				pLast[0] = pLast[0] + fTime
				del lData[iDatum]
			else:
				iDatum = iDatum + 1

			iLastFrame = iFrame

	def LeftClick(self, pEvent):
		# Get the position of the click, in the graph canvas.
		fXCoord = self.pCanvas.canvasx(pEvent.x)
		fYCoord = self.pCanvas.canvasy(pEvent.y)

		# Figure out which bit of data appears there.
		lTags = self.pCanvas.gettags( self.pCanvas.find_closest(fXCoord, fYCoord) )
		#print ("Min(%d), Max(%d), Got tags:" + str(lTags)) % (g_iFirstFrame, g_iLastFrame)
		iFrame = -1
		for sTag in lTags:
			try:
				iFrame = int(sTag)
			except ValueError: pass

		if iFrame >= g_iFirstFrame  and  iFrame <= g_iLastFrame:
 			# Search this frame.
 			print "Selected frame " + str(iFrame)
 			SearchFrames(self.dAllData.keys(), self.dAllData, self, iFrame)

	def AdjustArtificialYMax(self, pEvent):
		if self.fArtificialYMax is None:
			self.fArtificialYMax = askfloat("Set Artificial Maximum", "Enter new max:", parent=self)
			if self.fArtificialYMax <= 0.0:
				self.fArtificialYMax = None
		else:
			self.fArtificialYMax = None

		self.DrawGraph()

	def DrawGraph(self):
		self.focus_set()

		self.bDrawn = 1
		# Remove any old graphics.
		for idObject in self.pCanvas.find_all():
			self.pCanvas.delete(idObject)

		for idObject in self.pLeftTicks.find_all():
			self.pLeftTicks.delete(idObject)

		for pChild in self.pTextFrame.winfo_children():
			pChild.destroy()

		lAllData = []
		iGraphNum = 0
		iNumGraphs = len(self.llData)
		for lData in self.llData:
			for fTime, iFrame, iSeqStart, iSeqEnd in lData:
				lAllData.append( (iFrame, iGraphNum, fTime) )
			iGraphNum = iGraphNum + 1

		# Sort all the data by its frame number (then by graph number, then time).
		lAllData.sort()

		# Count the number of unique frames, and the maximum time value.
		iLastFrame = -1
		iNumFrames = 0
		fYMax = 0.0
		for iFrame, iGraphNum, fTime in lAllData:
			if iFrame != iLastFrame:
				iLastFrame = iFrame
				iNumFrames = iNumFrames + 1
			if fYMax < fTime:
				fYMax = fTime

		if iNumFrames < 1:
			from tkMessageBox import showerror
			showerror("Too little to graph", "%d unique frames; can't display graph." % iNumFrames)
			return

		# Scale the max value up a little, so the highest peak is still visible.
		if self.fArtificialYMax is not None:
			fYMax = self.fArtificialYMax
		else:
			fYMax = fYMax * 1.0125

		iWidth = self.pCanvas.winfo_width()
		iHeight = self.pCanvas.winfo_height()

		iLeftTickWidth = self.pLeftTicks.winfo_width()

		# Draw height lines and labels for the lines.
		iNumLines = 8
		self.pLeftTicks.create_line(iLeftTickWidth * 0.25, 1, iLeftTickWidth, 1, fill="black")
		pTopmostLabel = Label(self.pTextFrame, text="%5.4f" % fYMax)
		pTopmostLabel.place(rely=0.0)
		pTopmostLabel.bind("<Button-1>", self.AdjustArtificialYMax)
		for iLine in range(1, iNumLines):
			iLineY = iLine * iHeight / iNumLines
			self.pCanvas.create_line(0, iLineY, iWidth, iLineY, fill="#404040")
			self.pLeftTicks.create_line(iLeftTickWidth * 0.25, iLineY, iLeftTickWidth, iLineY, fill="black")

			fFraction = iLine / float(iNumLines)
			pLabel = Label(self.pTextFrame, text="%5.4f" % (fYMax * (1.0 - fFraction)))
			pLabel.update()
			pLabel.place(rely=fFraction - (10.0 / iHeight))

		# Draw the graph.
		iPoint = 0
		# A list of the last point drawn for each graph.
		lLastPoints = []
		for iGraph in range(iNumGraphs):
			lLastPoints.append( [-1.0, -1.0, -1] )

		iFrameNum = -1
		iLastUniqueFrame = -1
		for iFrame, iGraphNum, fTime in lAllData:
			# Count which frame we're on.  This determines the X position..
			if iFrame != iLastUniqueFrame:
				iFrameNum = iFrameNum + 1

			try:
				iPixelX = int(iWidth * (0.005 + 0.99 * iFrameNum / float(iNumFrames - 1)))
			except ZeroDivisionError:
				iPixelX = iWidth / 2

			iPixelY = int(iHeight - (iHeight * fTime / fYMax))

			# If this point is indistinguishable from the last point, don't draw it.
			bDraw = 1
			bConnect = 1
			iLastX, iLastY, iLastFrame = lLastPoints[iGraphNum]
			if (abs(iPixelX - iLastX) <= 2)  and  (abs(iPixelY - iLastY) <= 2):
				bDraw = 0
			if iLastFrame != iLastUniqueFrame:
				#bConnect = 0
				pass
			if iLastFrame == -1:
				bConnect = 0

			if bDraw:
				sColor = self.lColors[iGraphNum % len(self.lColors)]
				self.pCanvas.create_rectangle(iPixelX - 2, iPixelY - 2, iPixelX + 2, iPixelY + 2, outline=sColor, tags=(iFrame,))

				if bConnect:
					self.pCanvas.create_line(iLastX, iLastY, iPixelX, iPixelY, fill=sColor)

				# Save this position as the last position drawn.
				lLastPoints[iGraphNum][0] = iPixelX
				lLastPoints[iGraphNum][1] = iPixelY

			# Save this as the last frame looked at.
			lLastPoints[iGraphNum][2] = iFrame

			iLastUniqueFrame = iFrame

	def Resize(self, event = None):
		if self.bDrawn:
			self.bDrawn = 0
			self.after_idle(self.DrawGraph)
