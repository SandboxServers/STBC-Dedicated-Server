import App

# This script adds visual damage to an object
def AddDamage(pThingToDamage):
	pThingToDamage.AddObjectDamageVolume(0.033095, 0.810473, 0.093073, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.033095, 0.810473, 0.093074, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.033095, 0.810473, 0.093073, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.388792, -0.100312, 0.081554, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.464435, -0.163153, 0.037499, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.096696, -1.415151, 0.080072, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.096674, -1.404608, 0.080168, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.096674, -1.404608, 0.080168, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.883278, -0.099017, -0.008436, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.275739, -0.447621, 0.070867, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.183982, -0.338608, -0.232434, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.064873, -1.422892, -0.119009, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(0.804111, -0.118323, -0.063732, 0.400000, 300.000000)
	pThingToDamage.DamageRefresh(1)
