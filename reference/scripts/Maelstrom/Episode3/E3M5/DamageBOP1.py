import App

# This script adds visual damage to an object
def AddDamage(pThingToDamage):
	pThingToDamage.AddObjectDamageVolume(-0.744858, -0.116121, -0.375356, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.418613, -0.554681, -0.172949, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.040161, -0.591541, 0.023227, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.374783, -0.289875, -0.135026, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.532813, -0.422281, -0.237653, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.288325, -0.568580, -0.078878, 0.400000, 300.000000)
	pThingToDamage.DamageRefresh(1)
