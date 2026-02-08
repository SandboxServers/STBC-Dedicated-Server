import App

# This script adds visual damage to an object
def AddDamage(pThingToDamage):
	pThingToDamage.AddObjectDamageVolume(-0.189889, 1.072152, 0.125469, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.189888, 1.072153, 0.125468, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.189888, 1.072153, 0.125468, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.256762, -0.521359, 0.062626, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.287515, -0.678120, 0.003492, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.256690, -0.724123, -0.067305, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.112908, -1.871908, -0.068759, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.113730, -1.878361, -0.059431, 0.400000, 300.000000)
	pThingToDamage.DamageRefresh(1)
