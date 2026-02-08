#
# TurnToOrientation
#
# Turn our ship so a given modelspace vector points toward
# another object.  Optionally, we can also rotate to align
# a secondary vector (Up, perhaps) with a given modelspace
# vector on the object.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class TurnToOrientation(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetPrimaryDirection,
			self.SetSecondaryDirection,
			self.SetTargetCenterOffset,
			self.SetDoneOnLineup)
		self.SetRequiredParams( ( "sObject", "SetObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# Set the object that we're trying to move around.
	def SetObjectName(self, sObject): #AISetup
		self.sObject = sObject

	# Set the vector pointing to the side (in model space) that
	# we want to point toward the object.
	def SetPrimaryDirection(self, vDirection = App.TGPoint3_GetModelForward()): #AISetup
		self.vPrimaryDirection = App.TGPoint3()
		self.vPrimaryDirection.Set(vDirection)

	# Set the secondary vector that we want to align, for our
	# model, and the vector we want to align it with, on their
	# model.
	def SetSecondaryDirection(self, vDirection = None, vTargetDirection = None): #AISetup
		if vDirection:		
			self.vSecondaryDirection = App.TGPoint3()
			self.vSecondaryDirection.Set(vDirection)
		else:
			self.vSecondaryDirection = None

		if vTargetDirection:
			self.vSecondaryTargetDirection = App.TGPoint3()
			self.vSecondaryTargetDirection.Set(vTargetDirection)
		else:
			self.vSecondaryTargetDirection = None

	# If we want to point our vector to some component
	# of the other object, or some point around the other object
	# set a Center Offset (in the model space of the other object).
	def SetTargetCenterOffset(self, vModelSpaceOffset = None): #AISetup
		if vModelSpaceOffset:
			self.vCenterOffset = App.TGPoint3()
			self.vCenterOffset.Set(vModelSpaceOffset)
		else:
			self.vCenterOffset = None

	# Whether or not our status changes to Done when we
	# reach the orientation we're going for.  By default, we
	# remain Active.
	def SetDoneOnLineup(self, bDone = 0): #AISetup
		self.bDoneOnLineup = bDone




	fDoneDot = 0.95

	def GetStatusInfo(self):
		sSecondary = "None"
		if self.vSecondaryDirection:
			sSecondary = "%2.f,%2.f,%2.f" % (self.vSecondaryDirection.GetX(), self.vSecondaryDirection.GetY(), self.vSecondaryDirection.GetZ())
		if self.vSecondaryTargetDirection:
			sSecondary = sSecondary + ("%2.f,%2.f,%2.f" % (
				self.vSecondaryTargetDirection.GetX(), self.vSecondaryTargetDirection.GetY(), self.vSecondaryTargetDirection.GetZ()))

		sTargetCenterOffset = "None"
		if self.vCenterOffset:
			sTargetCenterOffset = "%2.f,%2.f,%2.f" % (self.vCenterOffset.GetX(), self.vCenterOffset.GetY(), self.vCenterOffset.GetZ())

		return "Target(%s), PrimaryDir<%.2f,%.2f,%.2f>, SecondaryDir<%s>, TargetCentOffs<%s>, DoneOnLineup(%d)" % (
			self.sObject,
			self.vPrimaryDirection.GetX(), self.vPrimaryDirection.GetY(), self.vPrimaryDirection.GetZ(),
			sSecondary,
			sTargetCenterOffset,
			self.bDoneOnLineup)

	def GetNextUpdateTime(self):
		return 0.5

	def Update(self):
		"Do our stuff"
		eRet = App.ArtificialIntelligence.US_DONE

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Set our speed to 0.
		pShip.SetSpeed(0, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		# Get the object we're turning toward.
		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.sObject)
		if pObject:
			# The object exists.  Find the center of this
			# object.
			vObjectCenter = App.TGPoint3()
			vObjectCenter.SetXYZ(0, 0, 0)
			if self.vCenterOffset:
				vObjectCenter.Add(self.vCenterOffset)
				vObjectCenter.MultMatrixLeft(pObject.GetWorldRotation())
			vObjectCenter.Add(pObject.GetWorldLocation())

			# Get information about this point.
			vDifference, fDistance, vDirection, fAngle = pShip.GetRelativePositionInfo(vObjectCenter)

			# Find our primary direction in world space.
			vPrimaryWorld = App.TGPoint3()
			vPrimaryWorld.Set(self.vPrimaryDirection)
			vPrimaryWorld.MultMatrixLeft( pShip.GetWorldRotation() )

			# If we have a secondary direction to align, make
			# sure it's perpendicular to vDirection.
			if self.vSecondaryDirection and self.vSecondaryTargetDirection:
				vSecondaryWorld = App.TGPoint3()
				vSecondaryWorld.Set(self.vSecondaryDirection)
				vSecondaryWorld.MultMatrixLeft( pShip.GetWorldRotation() )

				vSecondaryTargetWorld = App.TGPoint3()
				vSecondaryTargetWorld.Set(self.vSecondaryTargetDirection)
				vSecondaryTargetWorld.MultMatrixLeft( pObject.GetWorldRotation() )

				# Make sure it's perpendicular to vDirection.
				vCross = vDirection.Cross( vSecondaryTargetWorld )
				vSecondaryTargetWorld = vCross.Cross( vDirection )
				vSecondaryTargetWorld.Unitize()
			else:
				vSecondaryWorld = App.TGPoint3()
				vSecondaryWorld.SetXYZ(0, 0, 0)
				vSecondaryTargetWorld = App.TGPoint3()
				vSecondaryTargetWorld.SetXYZ(0, 0, 0)

			# Do the turn.
			fTime = pShip.TurnDirectionsToDirections(
				vPrimaryWorld, vDirection,
				vSecondaryWorld, vSecondaryTargetWorld)

			# If self.bDoneOnLineup is set and fTime is
			# very low, we're Done.
			bLinedUp = 1
			fPrimaryDot = vPrimaryWorld.Dot( vDirection )
			if vPrimaryWorld.Dot( vDirection ) < self.fDoneDot:
				bLinedUp = 0
			if self.vSecondaryDirection and self.vSecondaryTargetDirection:
				if vSecondaryWorld.Dot( vSecondaryTargetWorld ) < self.fDoneDot:
					bLinedUp = 0

			if self.bDoneOnLineup  and  bLinedUp:
				eRet = App.ArtificialIntelligence.US_DONE
			else:
				#debug(__name__ + ": Time is %f" % fTime)
				eRet = App.ArtificialIntelligence.US_ACTIVE

		return eRet
