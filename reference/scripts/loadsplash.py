#
# loadspash.py
#
# Loads the splash screen and forces the default camera to do the initial render
#
import App

g_pSplashPane = None

#
# Create the splash screen
#
# Store our created splash screen pane in a module global variable
#
def CreateSplashScreen():
	global g_pSplashPane
	# If a splash screen already exists, bail
	if (g_pSplashPane != None):
		return

	# Create our splash screen TGPane.  If we fail, bail out.
	g_pSplashPane = App.TGPane_Create(1.0, 1.0)
	if (g_pSplashPane == None):
		return

	# Add our splash screen icons to this pane
	pSplashScreen1 = App.TGIcon_Create("SplashScreen", 1)
	pSplashScreen1.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen1, 0, 0)

	pSplashScreen2 = App.TGIcon_Create("SplashScreen", 2)
	pSplashScreen2.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen2, 0.5, 0)

	pSplashScreen3 = App.TGIcon_Create("SplashScreen", 3)
	pSplashScreen3.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen3, 0, 0.5)

	pSplashScreen4 = App.TGIcon_Create("SplashScreen", 4)
	pSplashScreen4.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen4, 0.5, 0.5)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.TGL")
	pParagraph = App.TGParagraph_CreateW(pDatabase.GetString("Loading"), 1.0, App.NiColorA(0.65, 0.65, 1.0, 1.0), "Crillee", 16.0)
	g_pSplashPane.AddChild(pParagraph, 0.25 - 0.5*pParagraph.GetWidth(), 0.9 - 0.5*pParagraph.GetHeight())
	g_pSplashPane.MoveToFront(pParagraph)
	App.g_kLocalizationManager.Unload(pDatabase)

	g_pSplashPane.SetAlwaysHandleEvents()

	# Add the pane to the root window and move it to the front
	App.g_kRootWindow.AddChild(g_pSplashPane)
	App.g_kRootWindow.MoveToFront(g_pSplashPane)

	# Render splash screen
	App.g_kRootWindow.Layout()
	App.g_kUtopiaModule.RenderDefaultCamera()


def CreateLoadGameSplashScreen():
	global g_pSplashPane
	# If a splash screen already exists, bail
	if (g_pSplashPane != None):
		return

	# Create our splash screen TGPane.  If we fail, bail out.
	g_pSplashPane = App.TGPane_Create(1.0, 1.0)
	if (g_pSplashPane == None):
		return

	# Add our splash screen icons to this pane
	pSplashScreen1 = App.TGIcon_Create("SplashScreen", 1)
	pSplashScreen1.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen1, 0, 0)

	pSplashScreen2 = App.TGIcon_Create("SplashScreen", 2)
	pSplashScreen2.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen2, 0.5, 0)

	pSplashScreen3 = App.TGIcon_Create("SplashScreen", 3)
	pSplashScreen3.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen3, 0, 0.5)

	pSplashScreen4 = App.TGIcon_Create("SplashScreen", 4)
	pSplashScreen4.Resize(0.5, 0.5, 0)
	g_pSplashPane.AddChild(pSplashScreen4, 0.5, 0.5)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.TGL")
	pParagraph = App.TGParagraph_CreateW(pDatabase.GetString("Loading"), 1.0, App.NiColorA(0.65, 0.65, 1.0, 1.0), "Crillee", 16.0)
	g_pSplashPane.AddChild(pParagraph, 0.25 - 0.5*pParagraph.GetWidth(), 0.9 - 0.5*pParagraph.GetHeight())
	g_pSplashPane.MoveToFront(pParagraph)
	App.g_kLocalizationManager.Unload(pDatabase)

	g_pSplashPane.SetAlwaysHandleEvents()

	# Add the pane to the root window and move it to the front
	App.g_kRootWindow.AddChild(g_pSplashPane)
	App.g_kRootWindow.MoveToFront(g_pSplashPane)

	# Render splash screen
	App.g_kRootWindow.Layout()
	App.g_kUtopiaModule.RenderDefaultCamera()

#	print("Paragraph located at " + str(pParagraph.GetLeft()) + ", " + str(pParagraph.GetTop()))

	# This is only used during loading a saved game, during which the pane will
	# properly be destroyed, so we don't need a pointer to it.
	g_pSplashPane = None


#
# RemoveSplashScreen()
#
# If our g_pSplashPane variable is not 0 then it is our Splash screen
# TGPane, and deleting it will remove the splash screen
#
def RemoveSplashScreen():
	global g_pSplashPane
	if (g_pSplashPane != None):
		g_pSplashPane.Destroy()
		g_pSplashPane = None
