#
# ConditionWarpingToMission
#
# A condition that tests to see if an object is warping
# to a new mission.  If so, it's true.  If not, it's false.
#
import App
import ConditionWarpingToSet

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionWarpingToMission(ConditionWarpingToSet.ConditionWarpingToSet):
	def __init__(self, pCodeCondition, sObjectName):
		# Parent class init...
		ConditionWarpingToSet.ConditionWarpingToSet.__init__(self, pCodeCondition, sObjectName, None)

	def SetStateFromSequence(self, pWarpSequence):
		# Check if this warp sequence will bring the ship into a new mission (or a new episode, which
		# means a new mission).
		if pWarpSequence and (pWarpSequence.GetDestinationMission()  or  pWarpSequence.GetDestinationEpisode()):
			self.pCodeCondition.SetStatus(1)
		else:
			self.pCodeCondition.SetStatus(0)
