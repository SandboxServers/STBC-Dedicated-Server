import App
import MissionLib
import Actions.CameraScriptActions
import Actions.ShipScriptActions
import Camera

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

def SetupExitPositions(pShip, pStarbase):
	# Move the ship to the "Docking Exit" waypoint.
	pSet = pStarbase.GetContainingSet()
	pDockingEntry = App.PlacementObject_GetObject(pSet, "Docking Exit")

	vZero = App.TGPoint3()
	vZero.SetXYZ(0, 0, 0)
	pShip.SetVelocity(vZero)
	pShip.SetAngularVelocity(vZero, App.PhysicsObjectClass.DIRECTION_WORLD_SPACE)
	pShip.PlaceObjectByName("Docking Exit")
	pShip.UpdateNodeOnly()

def Undocked(pShip, sStarbase):
	# If this is the player, send an event saying that it's no longer docked.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer  and  (pPlayer.GetObjID() == pShip.GetObjID()):
		# Get the object docked with.
		pSet = pShip.GetContainingSet()
		if pSet:
			pStarbase = App.ShipClass_GetObject(pSet, sStarbase)
			if pStarbase:
				# Send the event.
				pEvent = App.TGBoolEvent_Create()
				pEvent.SetEventType(App.ET_PLAYER_DOCKED_WITH_STARBASE)
				pEvent.SetSource(pPlayer)
				pEvent.SetDestination(pStarbase)
				pEvent.SetBool(0)
				App.g_kEventManager.AddEvent(pEvent)

def MakeWaypoints(pStarbase):
	# Waypoints will be named "Docking Entry" and "Docking Entry End".
	# Get these waypoints if they exist, or create them if they don't.
	pWaypointStart = App.Waypoint_Cast( App.PlacementObject_GetObject(pStarbase.GetContainingSet(), "Docking Exit") )
	if not pWaypointStart:
		pWaypointStart = App.Waypoint_Create("Docking Exit", pStarbase.GetContainingSet().GetName(), None)
		pWaypointStart.SetSpeed(1.0)

	pWaypointEnd = App.Waypoint_Cast( App.PlacementObject_GetObject(pStarbase.GetContainingSet(), "Docking Exit End") )
	if not pWaypointEnd:
		pWaypointEnd = App.Waypoint_Create("Docking Exit End", pStarbase.GetContainingSet().GetName(), None)
		pWaypointEnd.SetSpeed(5.0)

	# Make sure the End waypoint is attached to the start waypoint.
	if (not pWaypointStart.GetNext())  or  (pWaypointStart.GetNext().GetObjID() != pWaypointEnd.GetObjID()):
		# It's not.  Attach it.
		pWaypointStart.InsertAfterObj(pWaypointEnd)

	# Position pWaypointStart at the "Docking Exit Start" position/orientation
	# on the starbase model, and pWaypointEnd at the "Docking Exit End" one.
	for pWaypoint, sHardpoint in (
		(pWaypointStart, "Docking Exit Start"),
		(pWaypointEnd, "Docking Exit End")
		):

		vPos, vFwd, vUp = MissionLib.GetPositionOrientationFromProperty(pStarbase, sHardpoint)
		if None in (vPos, vFwd, vUp):
			raise AttributeError, "Object (%s) has no position/orientation property (%s)" % (pStarbase.GetName(), sHardpoint)

		# Change these values to worldspace..
		import DockWithStarbase
		DockWithStarbase.PositionObjectFromLocalInfo(pWaypoint, pStarbase, vPos, vFwd, vUp)

def CreateAI(pShip, pStarbase):
	# Find the docking point on the starbase, in the
	# model space of the starbase.
	global vBayCenter, vBayDirection, vBayUp
	vBayCenter = None
	vBayDirection = None
	vBayUp = None

	MakeWaypoints(pStarbase)

	if pStarbase:
		pSet = pStarbase.GetContainingSet()
		if pSet:
			pBayWaypoint = App.Waypoint_Cast( App.PlacementObject_GetObject(pSet, "Docking Exit") )
			if pBayWaypoint:
				mInv = pStarbase.GetWorldRotation()

				# Determine the center of the docking
				# bay, in the starbase's model space.
				vBayCenter = pBayWaypoint.GetWorldLocation()
				vBayCenter.Subtract(pStarbase.GetWorldLocation())
				vBayCenter.MultMatrixLeft(mInv)
				vBayCenter.Scale( 1.0 / pStarbase.GetScale() )

				# Determine orientation.
				vBayDirection = pBayWaypoint.GetWorldForwardTG()
				vBayDirection.Scale(-1.0)
				vBayDirection.MultMatrixLeft(mInv)

				vBayUp = pBayWaypoint.GetWorldUpTG()
				vBayUp.MultMatrixLeft(mInv)

	if not (vBayCenter and vBayDirection and vBayUp):
		# Starbase doesn't have a docking point.  We can't
		# dock with it.
#		debug("Tried to dock with a starbase with no docking point: " + str(pStarbase.GetName()))
		return None

	#########################################
	# Creating PlainAI SetupExitPositions at (129, 117)
	pSetupExitPositions = App.PlainAI_Create(pShip, "SetupExitPositions")
	pSetupExitPositions.SetScriptModule("RunScript")
	pSetupExitPositions.SetInterruptable(1)
	pScript = pSetupExitPositions.GetScriptInstance()
	pScript.SetScriptModule(__name__)
	pScript.SetFunction("SetupExitPositions")
	pScript.SetArguments(pShip, pStarbase)
	# Done creating PlainAI SetupExitPositions
	#########################################
	#########################################
	# Creating PlainAI ExitStarbase at (235, 113)
	pExitStarbase = App.PlainAI_Create(pShip, "ExitStarbase")
	pExitStarbase.SetScriptModule("FollowWaypoints")
	pExitStarbase.SetInterruptable(1)
	pScript = pExitStarbase.GetScriptInstance()
	pScript.SetTargetWaypointName("Docking Exit")
	# Done creating PlainAI ExitStarbase
	#########################################
	#########################################
	# Creating PlainAI FinishedUndocking at (264, 164)
	pFinishedUndocking = App.PlainAI_Create(pShip, "FinishedUndocking")
	pFinishedUndocking.SetScriptModule("RunScript")
	pFinishedUndocking.SetInterruptable(1)
	pScript = pFinishedUndocking.GetScriptInstance()
	pScript.SetScriptModule(__name__)
	pScript.SetFunction("Undocked")
	pScript.SetArguments(pShip, pStarbase.GetName())
	# Done creating PlainAI FinishedUndocking
	#########################################
	#########################################
	# Creating SequenceAI UndockingSequence at (69, 261)
	pUndockingSequence = App.SequenceAI_Create(pShip, "UndockingSequence")
	pUndockingSequence.SetInterruptable(1)
	pUndockingSequence.SetLoopCount(1)
	pUndockingSequence.SetResetIfInterrupted(1)
	pUndockingSequence.SetDoubleCheckAllDone(0)
	pUndockingSequence.SetSkipDormant(0)
	# SeqBlock is at (193, 268)
	pUndockingSequence.AddAI(pSetupExitPositions)
	pUndockingSequence.AddAI(pExitStarbase)
	pUndockingSequence.AddAI(pFinishedUndocking)
	# Done creating SequenceAI UndockingSequence
	#########################################
	return pUndockingSequence
