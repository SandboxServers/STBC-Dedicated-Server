import App

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("Voltair", "Systems.Voltair.Voltair2",
							 "Systems.Voltair.Voltair1",
							 "Systems.Voltair.Voltair2")
