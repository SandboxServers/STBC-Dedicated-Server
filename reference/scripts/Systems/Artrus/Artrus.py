import App

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("Artrus", "Systems.Artrus.Artrus3",
										  "Systems.Artrus.Artrus1",
										  "Systems.Artrus.Artrus2",
										  "Systems.Artrus.Artrus3")
