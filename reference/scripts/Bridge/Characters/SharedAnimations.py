import App

# Load button press.  Use ID's < 1000 for shared animations.
# be shared by other people who are standing.

kAM = App.g_kAnimationManager

# Hit hard left
kAM.LoadAnimation ("data/animations/_hit_hard_left.nif", "hithardleft")

# Eyes open mouth close
kAM.LoadAnimation ("data/animations/eyes_open_mouth_close.nif", "eyes_open_mouth_close")

# Standing
kAM.LoadAnimation ("data/animations/standing.NIF", "standing") #2

# Pushing Buttons
kAM.LoadAnimation ("data/animations/pushing_buttons_a.NIF", "pushing_buttons_a")  #3
kAM.LoadAnimation ("data/animations/pushing_buttons_b.NIF", "pushing_buttons_b")  #4
kAM.LoadAnimation ("data/animations/pushing_buttons_c.NIF", "pushing_buttons_c")  #5
kAM.LoadAnimation ("data/animations/pushing_buttons_d.NIF", "pushing_buttons_d")  #6

# At Ease
kAM.LoadAnimation ("data/animations/_at_ease.NIF", "at_ease") #7		
kAM.LoadAnimation ("data/animations/_at_ease_looking_left.NIF", "at_ease_looking_left") #8
kAM.LoadAnimation ("data/animations/_at_ease_looking_right.NIF", "at_ease_looking_right") #9
#kAM.LoadAnimation ("data/animations/_at_ease_swaying_left.NIF", "at_ease_swaying_left") #10
#kAM.LoadAnimation ("data/animations/_at_ease_swaying_right.NIF", "at_ease_swaying_right") # 11

# Coughing
#kAM.LoadAnimation ("data/animations/_coughing_left.NIF", "coughing_left")	#Needs to be adjusted 12
#kAM.LoadAnimation ("data/animations/_coughing_right.NIF", "coughing_right)	#Needs to be adjusted 13

# Clapping
#kAM.LoadAnimation ("data/animations/_clapping.NIF", "clapping") #14

# Hands on Hips			
#kAM.LoadAnimation ("data/animations/_hands_on_hips.NIF", "hands_on_hips")	# This one needs to be fixed 16

# Fist hitting palms
#kAM.LoadAnimation ("data/animations/_fist_hitting_palm_left.NIF", "fist_hitting_palm_left")	#Needs to be adjusted 17
#kAM.LoadAnimation ("data/animations/_fist_hitting_palm_right.NIF", "fist_hitting_palm_right")	#Needs to be adjusted 18

# Pointing
kAM.LoadAnimation ("data/animations/_pointing_left.NIF", "pointing_left")	# 19		
kAM.LoadAnimation ("data/animations/_pointing_right.NIF", "pointing_right")	 # 20

# Nodding
kAM.LoadAnimation ("data/animations/nod.NIF", "_nod")		#Could be tweaked  21

# Waving
kAM.LoadAnimation ("data/animations/_waving_hi_left.NIF", "waving_hi_left")  #22
kAM.LoadAnimation ("data/animations/_waving_hi_right.NIF", "waving_hi_right")  #23

# Bridge crew shaking
kAM.LoadAnimation ("data/animations/db_hit_t.NIF", "db_hit_t") #100
kAM.LoadAnimation ("data/animations/db_hit_h.NIF", "db_hit_h") #101
kAM.LoadAnimation ("data/animations/db_hit_c.NIF", "db_hit_c") #102
kAM.LoadAnimation ("data/animations/standing_hit.NIF", "standing_hit") #103

# Ding, dong, the metaanimation is dead
# Replace these with Sequences

# Shakecrew
#pMetaAnim = App.MetaAnimationClass_Create ()
#pMetaAnim.AddAnimation ("Tactical", "bridge", "db_hit_t", 0.0, 1)
#pMetaAnim.AddAnimation ("Helm", "bridge", "db_hit_h", 0.0, 1)
#pMetaAnim.AddAnimation ("XO", "bridge", "db_hit_c", 0.0, 1)
#pMetaAnim.AddAnimation ("Science", "bridge", "standing_hit", 0.0, 1)
#pMetaAnim.AddAnimation ("Engineer", "bridge", "standing_hit", 0.0, 1)
#kMAM.AddMetaAnimation (pMetaAnim, "ShakeCrewSitting")

#pMetaAnim = App.MetaAnimationClass_Create ()
#pMetaAnim.AddAnimation ("Tactical", "bridge", "db_hit_t", 0.0, 1)
#pMetaAnim.AddAnimation ("Helm", "bridge", "db_hit_h", 0.0, 1)
#pMetaAnim.AddAnimation ("XO", "bridge", "db_hit_c", 0.0, 1)
#pMetaAnim.AddAnimation ("Science", "bridge", "standing_hit", 0.0, 1)
#pMetaAnim.AddAnimation ("Engineer", "bridge", "standing_hit", 0.0, 1)
#kMAM.AddMetaAnimation (pMetaAnim, "ShakeCrewStanding")

