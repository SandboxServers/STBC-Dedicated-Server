#
# ConditionDifficultyAt
#
# This condition is true if the game difficulty setting
# matches the given value.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionDifficultyAt:
	def __init__(self, pCodeCondition, eDifficulty = App.Game.MEDIUM):
		# Set our parameters...
		self.pCodeCondition = pCodeCondition
		self.eDifficulty = eDifficulty

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Check the game's difficulty setting.  Our status is true
		# if we match that setting, false if not.
		if App.Game_GetDifficulty() == self.eDifficulty:
			self.pCodeCondition.SetStatus(1)
		else:
			self.pCodeCondition.SetStatus(0)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

