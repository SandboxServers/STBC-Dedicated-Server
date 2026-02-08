import App

# This script adds visual damage to an object
def AddDamage(pThingToDamage):
	pThingToDamage.AddObjectDamageVolume(-0.507975, 0.154860, 0.018298, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.697906, -0.099181, -0.008440, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.069429, -0.648789, 0.100033, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.087177, 0.739282, 0.247122, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.063081, -0.039337, -0.264716, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.063082, -0.039336, -0.264716, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.811429, -0.090370, -0.063690, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.943594, -0.342492, -0.063663, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.943594, -0.342492, -0.063663, 0.400000, 300.000000)
	pThingToDamage.DamageRefresh(1)
