###############################################################################
#	Filename:	UITheme.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Sets up the default user interface theme with the UI theme manager.
#	
#	Created:	3/27/00 -	Erik Novales
###############################################################################
import App

#kDebugObj = App.CPyDebug()
kTM = App.g_kUIThemeManager

kTheme = App.TGUITheme_Create("default")
kTheme.SetWindowFrameName("Frame")
kTheme.SetWindowFrameScale(0.4)
kTheme.SetDialogFrameName("Frame")
kTheme.SetDialogFrameScale(0.4)
kTheme.SetButtonFrameName("FrameButton")
kTheme.SetButtonFrameScale(0.3)
kTM.AddTheme(kTheme)

kTM.SetCurrentTheme("default")

# These really aren't needed as globals.  Scrap them, so they don't
# mess up save & load.
del kTheme
del kTM
