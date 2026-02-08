#
# ConditionInNebula
#
# A condition that's true if the player's ship is in orbit
# around a specified planet.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionInNebula:
	def __init__(self, pCodeCondition, sObjectName, sNebulaName = None):
		# Set our object and set names...
		self.pCodeCondition = pCodeCondition
		self.sObject = sObjectName
		self.sNebulaName = sNebulaName
		self.lContainingNebulaNames = []

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Event handler...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Check if our object exists, and if it's in the nebula.
		pObject = App.ObjectClass_GetObject(None, self.sObject)
		if pObject:
			self.SetupFromObject(pObject)
		else:
			# No object.
			self.pCodeCondition.SetStatus(0)
			# Listen for when the object enters a set.
			App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet")

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetupFromObject(self, pObject):
		# Get all the nebulas in its set...
		pSet = pObject.GetContainingSet()
		if pSet:
			lNebulas = pSet.GetClassObjectList(App.CT_NEBULA)
			for pNebula in lNebulas:
				# If we have a nebula name, check if this nebula matches
				# that name.
				if (self.sNebulaName is not None) and (pNebula.GetName() != self.sNebulaName):
					# It doesn't match.	 Skip this nebula.
					continue
				# Check if the object is in this nebula.
				if pNebula.IsObjectInNebula(pObject):
					# Yep.
					self.lContainingNebulaNames.append( pNebula.GetName() )

		self.pCodeCondition.SetStatus( len(self.lContainingNebulaNames) > 0 )

		# Add handlers for when this object enters or exits a nebula.
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_ENTERED_NEBULA, self.pEventHandler, "EnteredNebula", pObject)
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_EXITED_NEBULA, self.pEventHandler, "ExitedNebula", pObject)
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_DELETE_OBJECT_PUBLIC, self.pEventHandler, "ObjectDeleted", pObject)

	def EnteredSet(self, pEvent):
		# Something entered a set.  Is it the object we're looking for?
		pObject = App.ObjectClass_Cast( pEvent.GetDestination() )
		if pObject and (pObject.GetName() == self.sObject):
			# Yep, it's our object.
			self.SetupFromObject(pObject)
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet")

	def EnteredNebula(self, pEvent):
		# Our object has entered a nebula.
		pNebula = App.Nebula_Cast( pEvent.GetSource() )

		# If we have a nebula name restriction, check if this is the right
		# nebula.
		sNebulaName = pNebula.GetName()
		if (self.sNebulaName is not None)  and  (sNebulaName != self.sNebulaName):
			# Doesn't match.
			return

		# Add this nebula name to the list of nebulas that contain the ship, if
		# it's not already in the list.
		if (sNebulaName not in self.lContainingNebulaNames):
			self.lContainingNebulaNames.append( sNebulaName )

		# Our condition is True.
		if self.pCodeCondition.GetStatus() != 1:
			self.pCodeCondition.SetStatus(1)

	def ExitedNebula(self, pEvent):
		# Our object has exited a nebula.
		pNebula = App.Nebula_Cast( pEvent.GetSource() )

		# If we have a nebula name restriction, check if this is the right
		# nebula.
		sNebulaName = pNebula.GetName()
		if (self.sNebulaName is not None)  and  (sNebulaName != self.sNebulaName):
			# Doesn't match.
			return

		# Remove this nebula name from the list of nebulas that contain the ship.
		try:
			self.lContainingNebulaNames.remove( sNebulaName )
		except ValueError:
			pass
#			debug("Exited nebula that wasn't in the list: " + str(sNebulaName))

		# Our condition is only true if there are still nebulas containing us.
		bStatus = (len(self.lContainingNebulaNames) > 0)
		#debug("Exited nebula.  Still in: %s" % (str(self.lContainingNebulaNames)))
		if self.pCodeCondition.GetStatus() != bStatus:
			self.pCodeCondition.SetStatus(bStatus)

	def ObjectDeleted(self, pEvent):
		# Our object has been deleted.
		# It's not in any nebulas anymore.
		self.lContainingNebulaNames = []
		if self.pCodeCondition.GetStatus() != 0:
			self.pCodeCondition.SetStatus(0)



