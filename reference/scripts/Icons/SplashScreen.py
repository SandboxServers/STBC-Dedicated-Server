# SplashScreen.py
#
import App

def LoadSplashScreen(SplashScreen = None):
	
	if SplashScreen is None:
		SplashScreen = App.g_kIconManager.CreateIconGroup("SplashScreen");
		App.g_kIconManager.AddIconGroup(SplashScreen)

	Splash1 = SplashScreen.LoadIconTexture("Data/Icons/Splash1.tga")
	Splash2 = SplashScreen.LoadIconTexture("Data/Icons/Splash2.tga")
	Splash3 = SplashScreen.LoadIconTexture("Data/Icons/Splash3.tga")
	Splash4 = SplashScreen.LoadIconTexture("Data/Icons/Splash4.tga")
	
	SplashScreen.SetIconLocation(1, Splash1, 0, 0, 256, 256)
	SplashScreen.SetIconLocation(2, Splash2, 0, 0, 256, 256)
	SplashScreen.SetIconLocation(3, Splash3, 0, 0, 256, 256)
	SplashScreen.SetIconLocation(4, Splash4, 0, 0, 256, 256)
	
	
