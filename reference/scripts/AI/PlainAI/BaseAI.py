#
# BaseAI
#
# This is the base AI script class that all the AI's need to
# inherit from.  It provides basic functionality that is needed
# across all AI's.
#
# AIEditor flags: NOTINLIST

class BaseAI:
	# Base class initialization.  All inheriting classes
	# need to call this function in their __init__ functions
	# (if they have them).
	def __init__(self, pCodeAI):
		# Save a copy of the C object that refers to this AI.
		self.pCodeAI = pCodeAI
		self.lRequiredParams = ()

	def __getstate__(self):
		dState = self.__dict__.copy()
		if hasattr(self, "pModule"):
			dState["pModule"] = self.pModule.__name__
		if hasattr(self, "pEventHandler"):
			dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		if hasattr(self, "pModule"):
			self.pModule = __import__(self.pModule)
		if hasattr(self, "pEventHandler"):
			del self.pEventHandler.pContainingInstance

	# Changing the pCodeAI pointer.  This is necessary for
	# save/load, since the pointer won't be accurate when the
	# script is loaded again.
	def FixCodeAI(self, pCodeAI):
		self.pCodeAI = pCodeAI

	# Setting up default parameters..
	def SetupDefaultParams(self, *lpFunctions):
		self.iSetup = 1
		for pFunction in lpFunctions:
			pFunction()
		self.iSetup = 0

	# Checking that required parameters have been set.
	def SetRequiredParams(self, *lAttributeFunctionPairs):
		self.lRequiredParams = list(lAttributeFunctionPairs)

	# Setting up externally registered functions.
	def SetExternalFunctions(self, *lFunctions):
		for sExternalName, sFunctionName in lFunctions:
			self.pCodeAI.RegisterExternalFunction( sExternalName, {"Name": sFunctionName} )

	# Activation/deactivation functions, for use with Interrupting
	# AI's.  If an AI is becoming active or inactive, its
	# interrupting AI's may also need to be activated or
	# deactivated.  Use these functions to do that.
	def Activate(self):
		# Check that required parameters have been filled in.
		for sAttribute, sFunction in self.lRequiredParams:
			if not hasattr(self, sAttribute):
				raise AttributeError, "AI activated before calling %s.%s" % (str(self.__class__), sFunction)

		# If we made it this far, all attributes are present, and we
		# can stop checking.
		self.lRequiredParams = ()

		# If we're the only version of Activate for this class instance, tell
		# the code AI to stop calling us.  If this instance is from a derived
		# class with its own Activate, this comparison will be false.
		if self.Activate.im_func == BaseAI.Activate.im_func:
			self.pCodeAI.StopCallingActivate()
