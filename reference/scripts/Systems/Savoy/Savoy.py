import App

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("Savoy", "Systems.Savoy.Savoy3",
							 "Systems.Savoy.Savoy1",
							 "Systems.Savoy.Savoy2",
							 "Systems.Savoy.Savoy3")
