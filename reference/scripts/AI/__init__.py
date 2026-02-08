# Empty file.  This needs to be here so statements like
# "import AI.Module" will work.

# There's no point in unloading this module as missions or
# episodes go away.  Make it persistent at the episode level.
# During serialization/unserialization, the current game will
# be None, and we don't want to call AddPersistentModule then anyways.
import App
pGame = App.Game_GetCurrentGame()
if pGame:
	pEpisode = pGame.GetCurrentEpisode()
	if pEpisode:
		pEpisode.AddPersistentModule("AI")
	del pEpisode
del pGame
del App
# del's are there because I don't want pEpisode and pGame global variables sticking around.
