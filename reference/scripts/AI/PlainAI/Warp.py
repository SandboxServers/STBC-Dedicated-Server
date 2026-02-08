#
# Warp
#
# Warp immediately.  If a set is specified, warp to the specified set.
# If no set is specified, the ship just warps out and disappears, never
# to be seen again.  The ship will be deleted.
# If the set is invalid (the name doesn't correspond to any existing
# set), this will treat it the same as if no set were specified.
# If a placement is specified, warp in so we land on that placement in
# the new set.
# If no placement is specified, warp in and land on the default warp
# entry placement for that set.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

ET_TOW_INCREMENT = App.UtopiaModule_GetNextEventType()
ET_AI_EXITED_WARP = App.UtopiaModule_GetNextEventType()

def WarpDoneAction(pAction, idAI):
	# Get the AI's script instance.
	pWarpAI = App.ArtificialIntelligence_GetAIByID(idAI)
	if pWarpAI:
		pScript = pWarpAI.GetScriptInstance()
		# Tell it it's done warping.
		pScript.WarpDone(None)

	return 0

g_dTowingToToweeMatches = {}

def TowIncrement(pTowTarget, pEvent = None):
	# Get the AI that initiated this, so we can get info from it.
	pWarpAI = App.ArtificialIntelligence_GetAIByID(pEvent.GetInt())
	if pWarpAI:
		pShip = pWarpAI.GetShip()
		if pShip:
			# If the tow target is in a different set from the ship, move it
			# to the same set.
			pTowSet = pTowTarget.GetContainingSet()
			pShipSet = pShip.GetContainingSet()
			if pShipSet:
				if not pTowSet:
					# If the target isn't in a set, don't touch it.
					return
				elif pTowSet.GetName() != pShipSet.GetName():
#					debug("Warp moving object %s after object %s, from set %s to set %s" %
#						  (pTowTarget.GetName(), pShip.GetName(), pTowSet.GetName(), pShipSet.GetName()))
					pTowSet.RemoveObjectFromSet( pTowTarget.GetName() )
					pShipSet.AddObjectToSet(pTowTarget, pTowTarget.GetName())

				# Move the target to its correct relative position.
				vPosition = App.TGPoint3()
				vPosition.Set( pWarpAI.GetScriptInstance().vTowPosition )
				vPosition.MultMatrixLeft( pShip.GetWorldRotation() )
				vPosition.Add( pShip.GetWorldLocation() )
				pTowTarget.SetTranslate(vPosition)

				#debug("Warp towing object %s after object %s" % (pTowTarget.GetName(), pShip.GetName()))

				# Set it to match velocities.
				pPhys = App.PhysicsObjectClass_Cast(pTowTarget)
				if pPhys:
					pPhys.SetVelocity( pShip.GetVelocityTG() )

		# Done for this frame.  Setup another timer that'll hit next frame.
		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(ET_TOW_INCREMENT)
		pEvent.SetDestination(pTowTarget)
		pEvent.SetInt(pWarpAI.GetID())

		pTimer = App.TGTimer_Create()
		pTimer.SetEvent(pEvent)
		pTimer.SetTimerStart( App.g_kUtopiaModule.GetGameTime() + 0.001 ) # Every 1000th of a second should be a short enough time.
		idTimer = pTimer.GetObjID()
		App.g_kTimerManager.AddTimer(pTimer)

		pWarpAI.GetScriptInstance().idTowTimer = idTimer

def TowingShipDeleted(pTowingShip, pDeletionEvent):
	try:
		# Look for this ship in the Towing to Towee dictionary.
		try:
			idTowee = g_dTowingToToweeMatches[pTowingShip.GetObjID()]
		except KeyError: return

		# Get the towed object.
		pTowTarget = App.ObjectClass_GetObjectByID(None, idTowee)
		if pTowTarget:
			# If it's in a set, have it delete itself.
			pTowTarget.SetDeleteMe(1)
#			debug("Warp deleting object %s" % pTowTarget.GetName())

		# Remove this pair from the dictionary.  We're done with it.
		del g_dTowingToToweeMatches[pTowingShip.GetObjID()]

	# Always call the next handler before we exit.
	finally:
		pTowingShip.CallNextHandler(pDeletionEvent)

def TowingShipEnteredSet(pTowingShip, pEvent):
	try:
		# Look for this ship in the Towing to Towee dictionary.
		try:
			idTowee = g_dTowingToToweeMatches[pTowingShip.GetObjID()]
		except KeyError: return

		# Get the towed object.
		pTowTarget = App.ObjectClass_GetObjectByID(None, idTowee)
		if not pTowTarget:
			return

		# Get the set we were just moved into.
		pSet = pTowingShip.GetContainingSet()
		if pSet:
			# Move the towed ship into the new set.  Don't
			# touch it if it's not in a set, though, because
			# that probably means it's in the process of being
			# deleted.
			pTowSet = pTowTarget.GetContainingSet()
			if pTowSet  and  (pTowSet.GetName() != pSet.GetName()):
#				debug("Warp, event handler moving object %s after object %s, from set %s to set %s" %
#					  (pTowTarget.GetName(), pTowingShip.GetName(), pTowSet.GetName(), pSet.GetName()))

				pTowSet.RemoveObjectFromSet(pTowTarget.GetName())
				pSet.AddObjectToSet(pTowTarget, pTowTarget.GetName())

	# Always call the next handler before we exit.
	finally:
		pTowingShip.CallNextHandler(pEvent)

class Warp(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Base class init, first..
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetDestinationSetName,
			self.SetDestinationPlacementName,
			self.SetWarpDuration,
			self.WarpBlindly,
			self.WarpBlindlyNoCollisionsIfImpulseDisabled,
			self.EnableTowingThroughWarp)
		self.SetRequiredParams()
		self.SetExternalFunctions()

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# We need an event handler...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		self.pEventHandler.AddPythonMethodHandlerForInstance( ET_AI_EXITED_WARP, "WarpDone" )

		# Initialize variables...
		self.bWarping = 0
		self.bCollisionsDisabled = 0
		self.eUpdateReturn = App.ArtificialIntelligence.US_ACTIVE
		self.pWarpSequence = None

		self.vTowPosition = None
		self.idTowObject = App.NULL_ID
		self.idTowTimer = App.NULL_ID

		self.vBetterDirection = None
		self.fDirectionTimeThreshold = 0.2



	# Name of the set we're going to.
	def SetDestinationSetName(self, sSetName = None): #AISetup
		self.sToSetName = sSetName

	def SetDestinationPlacementName(self, sPlacementName = None): #AISetup
		self.sPlacementName = sPlacementName

	def SetWarpDuration(self, fTime = 3.0): #AISetup
		self.fWarpTime = fTime

	def WarpBlindly(self, bWarpImmediately = 0): #AISetup
		self.bWarpImmediately = bWarpImmediately

	def WarpBlindlyNoCollisionsIfImpulseDisabled(self, bWarpBlindly = 0): #AISetup
		self.bWarpBlindlyIfNoImpulse = bWarpBlindly

	def EnableTowingThroughWarp(self, bTowThroughWarp = 0): # NOT an AISetup function.  Add it by hand.
		self.bEnableTowing = bTowThroughWarp

	# To force Warp to use this WarpSequence, rather than
	# creating its own.  This is not normally accessible to
	# the AI Editor, but it is used by the game.
	def SetSequence(self, pWarpSequence):
		#debug("Received warp sequence: " + str(pWarpSequence))
		self.pWarpSequence = pWarpSequence

		# Need to add an action to the end of the warp
		# sequence to call our WarpDone member, since
		# this probably won't send the event to the right place.
		pWarpDoneAction = App.TGScriptAction_Create(__name__, "WarpDoneAction", self.pCodeAI.GetID())
		self.pWarpSequence.AddActionAfterWarp(pWarpDoneAction, 0)




	def Reset(self):
		# Reset any state info
		self.bWarping = 0

	def LostFocus(self):
		# If we were towing, stop towing.
		self.StopTowing(self.pCodeAI.GetShip())
		# If we'd disabled collisions for our ship, reenable them.
		if self.bCollisionsDisabled:
			pShip = self.pCodeAI.GetShip()
			if pShip:
				pShip.SetCollisionsOn(1)
			self.bCollisionsDisabled = 0


	def GetStatusInfo(self):
		return "Destination(%s), Placement(%s), Duration(%f), Blind(%d), BlindIfDisabledImpulse(%d)%s" % (
			self.sToSetName,
			self.sPlacementName,
			self.fWarpTime,
			self.bWarpImmediately,
			self.bWarpBlindlyIfNoImpulse,
			("", ", Towing")[self.bEnableTowing])

	def GetNextUpdateTime(self):
		# We want to be updated every 1.0 seconds (+/- 0.2)
		fRandomFraction = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
		return 1.0 + (fRandomFraction * 0.2)

	def Update(self):
		"Do our stuff"
		# Default return is Done.
		eRet = App.ArtificialIntelligence.US_DONE

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Check power of engines.
		pEngines = pShip.GetImpulseEngineSubsystem()
		if pEngines:
			# If no power, then at least give enough to get going.
			if pEngines.GetPowerPercentageWanted() <= 0.0:
				pEngines.SetPowerPercentageWanted(1.0)
				pEngines.TurnOn()

		pWarp = pShip.GetWarpEngineSubsystem()
		if pWarp and (pWarp.GetPowerPercentageWanted() <= 0.0):
			pWarp.SetPowerPercentageWanted(1.0)
			pWarp.TurnOn()

		# Set our speed to 0.
		pShip.SetSpeed(0, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
		
		# Set our turning to 0.
		vZero = App.TGPoint3()
		vZero.SetXYZ(0, 0, 0)
		pShip.SetTargetAngularVelocityDirect( vZero )

		# If we haven't started the warp sequence yet, start it:
		if self.bWarping == 0:
			# Should we warp immediately, or aim for a good
			# direction first?
			bWarpImmediately = self.bWarpImmediately
			if self.bWarpBlindlyIfNoImpulse:
				# Check the state of our ship's impulse engines.  If they're disabled,
				# we want to warp immediately, without searching for a good direction.
				pImpulse = pShip.GetImpulseEngineSubsystem()
				if (not pImpulse)  or  (pImpulse.IsDisabled()):
					bWarpImmediately = 1

					# And disable collisions for this object...
					self.bCollisionsDisabled = 1
					pShip.SetCollisionsOn(0)

			if not bWarpImmediately:
				# Aim for a good direction.
				if not self.AimForGoodDirection(pShip):
					# Not yet facing a good direction.
					return App.ArtificialIntelligence.US_ACTIVE

			# Setup the warp sequence.
			if self.pWarpSequence == None:
				pWarpSeq = App.WarpSequence_Create(pShip, self.sToSetName, self.fWarpTime, self.sPlacementName)

				# Set the warp sequence to send us an event when
				# it's done (as long as we still exist).
				pEvent = App.TGEvent_Create()
				pEvent.SetEventType( ET_AI_EXITED_WARP )
				pEvent.SetDestination( self.pEventHandler )
				pWarpSeq.AddCompletedEvent(pEvent)

				pWarpSeq.SetEventDestination( pShip )
			else:
				pWarpSeq = self.pWarpSequence
				self.pWarpSequence = None

			# If we're towing a ship, save the info we need to do that.
			if self.bEnableTowing:
				self.SetupTowing(pShip)

			# Play the sequence.
			pWarpSeq.Play()

			# Set the bWarping flag, so we know we're warping now.
			self.bWarping = 1

			# Let the game know we're active.
			eRet = self.eUpdateReturn = App.ArtificialIntelligence.US_ACTIVE
		else:
			# We've already started warping.  Just return
			# whatever our state is..  The event handler for
			# when we come out of warp will set this to Done.
			#debug("Warping, warping...")
			eRet = self.eUpdateReturn

		return eRet

	def WarpDone(self, pEvent):
		"Our warp sequence has finished."
		# Next time we're updated, we can say we're done.
		#debug("Warping FINISHED")
		self.eUpdateReturn = App.ArtificialIntelligence.US_DONE

	def AimForGoodDirection(self, pShip):
		# Get all the objects along the line that we'll
		# be warping through.
		fRayLength = 4000.0
		vOrigin = pShip.GetWorldLocation()
		vEnd = pShip.GetWorldForwardTG()
		vEnd.Scale(fRayLength)
		vEnd.Add(vOrigin)

		lsObstacles = self.GrabObstacles(vOrigin, vEnd, pShip)
		# If we have no obstacles in the way, we're good.
		if len(lsObstacles) == 0:
			vZero = App.TGPoint3()
			vZero.SetXYZ(0, 0, 0)
			pShip.SetTargetAngularVelocityDirect(vZero)
			return 1

		#debug(__name__ + ": Turning to avoid %d obstacles." % len(lsObstacles))
		#for sObstacle in lsObstacles:
		#	debug(__name__ + ": Obstacle: " + str(sObstacle))

		# We've got obstacles in the way.
		if not self.vBetterDirection:
			# Cast a few rays
			# and try to find a good direction to go.  If we don't
			# find a good direction, that's ok; we'll try again
			# next frame.
			for iRayCount in range(8):
				vRay = App.TGPoint3_GetRandomUnitVector()

				# Bias it toward our Forward direction.
				vRay.Scale(1.5)
				vRay.Add(pShip.GetWorldForwardTG())

				vRay.Unitize()

				vEnd = App.TGPoint3()
				vEnd.Set(vRay)
				vEnd.Scale(fRayLength)

				vEnd.Add(vOrigin)
				lsObstacles = self.GrabObstacles(vOrigin, vEnd, pShip)
				if not lsObstacles:
					# Found a good direction.
					self.vBetterDirection = vRay
					break

		if self.vBetterDirection:
			#debug("Aiming for better direction.")
			fTime = pShip.TurnTowardDirection(self.vBetterDirection)
			if fTime < self.fDirectionTimeThreshold:
				# We're almost facing it, and still
				# no good.  Toss out this direction
				# so we try again next frame.
				self.vBetterDirection = None
#		else:
#			debug("Can't find a good direction...")
		return 0

	def GrabObstacles(self, vStart, vEnd, pShip):
		import MissionLib
		return MissionLib.GrabWarpObstaclesFromSet(vStart, vEnd, pShip.GetContainingSet(), pShip.GetRadius(), 1, pShip.GetObjID())

	def SetupTowing(self, pShip):
		# Figure out if we're towing a ship right now.
		pTractor = pShip.GetTractorBeamSystem()
		if (not pTractor)  or  (not pTractor.IsOn())  or  (pTractor.IsDisabled()):
			return

		# Tractor beam mode needs to be set to Tow, and must be firing.
		if (pTractor.GetMode() != App.TractorBeamSystem.TBS_TOW)  or  (not pTractor.IsTryingToFire()):
			return

		# ***FIXME: We're assuming that, just because we're firing, we're
		# hitting the right target.
		try:
			pTarget = pTractor.GetTargetList()[0]
			if not pTarget:
				return
		except IndexError: return

		# Got the target.  Save its position relative to us.
		self.vTowPosition = pTarget.GetWorldLocation()
		self.vTowPosition.Subtract( pShip.GetWorldLocation() )
		self.vTowPosition.MultMatrixLeft( pShip.GetWorldRotation().Transpose() )

		# And save its ID, so we know who we're towing.
		self.idTowObject = pTarget.GetObjID()

		g_dTowingToToweeMatches[ pShip.GetObjID() ] = pTarget.GetObjID()

		# Start the towing updates.
		pTarget.AddPythonFuncHandlerForInstance(ET_TOW_INCREMENT, __name__ + ".TowIncrement")
		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(ET_TOW_INCREMENT)
		pEvent.SetDestination(pTarget)
		pEvent.SetInt(self.pCodeAI.GetID())
		App.g_kEventManager.AddEvent( pEvent )

		# Setup a handler in case our ship is deleted.
		pShip.AddPythonFuncHandlerForInstance(App.ET_DELETE_OBJECT_PUBLIC, __name__ + ".TowingShipDeleted")

		# Setup another handler for when our ship enters a new set.
		pShip.AddPythonFuncHandlerForInstance(App.ET_ENTERED_SET, __name__ + ".TowingShipEnteredSet")

		# Disable collisions between the tower and towee.
		pDamTarget = App.DamageableObject_Cast(pTarget)
		pShip.EnableCollisionsWith(pDamTarget, 0)

	def StopTowing(self, pShip):
		# Stop the towing updates.
		#debug("StopTowing.  Map is " + str(g_dTowingToToweeMatches))
		App.g_kTimerManager.DeleteTimer( self.idTowTimer )

		# Remove the instance handlers on our ship.
		pShip.RemoveHandlerForInstance(App.ET_DELETE_OBJECT_PUBLIC, __name__ + ".TowingShipDeleted")
		pShip.RemoveHandlerForInstance(App.ET_ENTERED_SET, __name__ + ".TowingShipEnteredSet")

		try:
			pTarget = App.ObjectClass_GetObjectByID(pShip.GetContainingSet(), g_dTowingToToweeMatches[pShip.GetObjID()])
			# Remove this pair from the dictionary.  We're done with it.
			del g_dTowingToToweeMatches[pShip.GetObjID()]
		except KeyError:
			pTarget = None

		if pTarget:
			pTarget.RemoveHandlerForInstance(ET_TOW_INCREMENT, __name__ + ".TowIncrement")

			pDamTarget = App.DamageableObject_Cast(pTarget)
			pShip.EnableCollisionsWith(pDamTarget, 1)
