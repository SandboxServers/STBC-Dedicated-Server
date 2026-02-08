import App

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("Poseidon", "Systems.Poseidon.Poseidon2",
							 "Systems.Poseidon.Poseidon1",
							 "Systems.Poseidon.Poseidon2")
