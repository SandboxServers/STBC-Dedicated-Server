import App

#
#	FontsAndIcons.py
#
# This file registers all fonts and icons in the system
#

# Fonts - First font is default font
#
App.g_kFontManager.RegisterFont("Crillee", 5, "Crillee5", "LoadCrillee5")
App.g_kFontManager.RegisterFont("Crillee", 6, "Crillee6", "LoadCrillee6")
App.g_kFontManager.RegisterFont("Crillee", 9, "Crillee9", "LoadCrillee9")
App.g_kFontManager.RegisterFont("Crillee", 12, "Crillee12", "LoadCrillee12")
App.g_kFontManager.RegisterFont("Crillee", 15, "Crillee15", "LoadCrillee15")
App.g_kFontManager.RegisterFont("LCARSText", 5, "LCARSText5", "LoadLCARSText5")
App.g_kFontManager.RegisterFont("LCARSText", 6, "LCARSText6", "LoadLCARSText6")
App.g_kFontManager.RegisterFont("LCARSText", 9, "LCARSText9", "LoadLCARSText9")
App.g_kFontManager.RegisterFont("LCARSText", 12, "LCARSText12", "LoadLCARSText12")
App.g_kFontManager.RegisterFont("LCARSText", 15, "LCARSText15", "LoadLCARSText15")
App.g_kFontManager.RegisterFont("Tahoma", 8, "Tahoma", "LoadTahoma")
App.g_kFontManager.RegisterFont("Tahoma", 14, "TahomaLarge", "LoadTahomaLarge")
App.g_kFontManager.RegisterFont("Arial", 8, "Arial", "LoadArial")
App.g_kFontManager.RegisterFont("Serpentine", 12, "Serpentine12", "LoadSerpentine12")

# Icons
#
App.g_kIconManager.RegisterIconGroup("Console", "Console", "LoadConsole")
App.g_kIconManager.RegisterIconGroup("LCARS_640", "LCARS_640", "LoadLCARS_640")
App.g_kIconManager.RegisterIconGroup("LCARS_800", "LCARS_800", "LoadLCARS_800")
App.g_kIconManager.RegisterIconGroup("LCARS_1024", "LCARS_1024", "LoadLCARS_1024")
App.g_kIconManager.RegisterIconGroup("LCARS_1280", "LCARS_1280", "LoadLCARS_1280")
App.g_kIconManager.RegisterIconGroup("LCARS_1600", "LCARS_1600", "LoadLCARS_1600")
App.g_kIconManager.RegisterIconGroup("ShipIcons", "ShipIcons", "LoadShipIcons")
App.g_kIconManager.RegisterIconGroup("DamageIcons", "DamageIcons", "LoadDamageIcons")
App.g_kIconManager.RegisterIconGroup("SplashScreen", "SplashScreen", "LoadSplashScreen")
App.g_kIconManager.RegisterIconGroup("Frame", "Frame", "LoadFrame")
App.g_kIconManager.RegisterIconGroup("System", "SystemIcons", "LoadSystemIcons")
App.g_kIconManager.RegisterIconGroup("FrameButton", "FrameButton", "LoadFrameButton")
App.g_kIconManager.RegisterIconGroup("TargetArrow", "TargetArrow", "LoadTargetArrows")
App.g_kIconManager.RegisterIconGroup("WeaponIcons", "WeaponIcons", "LoadWeaponIcons")
App.g_kIconManager.RegisterIconGroup("NormalStyleFrame", "StylizedWindow", "LoadNormalStyleFrame")
