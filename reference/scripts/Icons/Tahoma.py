import App

# Function to load Tahoma font.
def LoadTahoma(Tahoma = None):
	
	if Tahoma is None:
		# Create font group.
		Tahoma = App.g_kFontManager.CreateFontGroup("Tahoma", 8.0)
		# Add Tahoma font group to FontManager
		App.g_kFontManager.AddFontGroup(Tahoma)

	# Load font texture
	pTextureHandle = Tahoma.LoadIconTexture('Data/Icons/Tahoma.tga')

	# Special characters
	Tahoma.SetIconLocation(0,				pTextureHandle, 48,  91,  5,  9) # Box shape
	Tahoma.SetIconLocation(App.WC_CURSOR,	pTextureHandle,  9,  40,  1, 10) # Cursor
	Tahoma.SetIconLocation(App.WC_TAB,		pTextureHandle,  0, 110,  1, 10) # Tab
	Tahoma.SetIconLocation(App.WC_SPACE,	pTextureHandle,  0, 110,  1, 10) # Space

	# Define icon locations
	Tahoma.SetIconLocation( 33, pTextureHandle,   0,  0,   1,  10) #	 !
	Tahoma.SetIconLocation( 34, pTextureHandle,   2,  0,   3,  10) #	 "
	Tahoma.SetIconLocation( 35, pTextureHandle,   6,  0,  7,  10) #	 #
	Tahoma.SetIconLocation( 36, pTextureHandle,  14,  0,  5,  10) #	 $
	Tahoma.SetIconLocation( 37, pTextureHandle,  20,  0,  9,  10) #	 %
	Tahoma.SetIconLocation( 38, pTextureHandle,  30,  0,  6,  10) #	 &
	Tahoma.SetIconLocation( 39, pTextureHandle,  37,  0,  1,  10) #	 '
	Tahoma.SetIconLocation( 40, pTextureHandle,  39,  0,  3,  10) #	 (
	Tahoma.SetIconLocation( 41, pTextureHandle,  43,  0,  3,  10) #	 )
	Tahoma.SetIconLocation( 42, pTextureHandle,  47,  0,  5,  10) #	 *
	Tahoma.SetIconLocation( 43, pTextureHandle,  53,  0,  5,  10) #	 +
	Tahoma.SetIconLocation( 44, pTextureHandle,  59,  0,  2,  10) #	 ,
	Tahoma.SetIconLocation( 45, pTextureHandle,  62,  0,  3,  10) #	 -
	Tahoma.SetIconLocation( 46, pTextureHandle,  66,  0,  1,  10) #	 .
	Tahoma.SetIconLocation( 47, pTextureHandle,  68,  0,  4,  10) #	 /
	Tahoma.SetIconLocation( 48, pTextureHandle,  73,  0,  4,  10) #	 0
	Tahoma.SetIconLocation( 49, pTextureHandle,  78,  0,  3,  10) #	 1
	Tahoma.SetIconLocation( 50, pTextureHandle,  82,  0,  4,  10) #	 2
	Tahoma.SetIconLocation( 51, pTextureHandle,  87,  0,  4,  10) #	 3
	Tahoma.SetIconLocation( 52, pTextureHandle,  92,  0,  5,  10) #	 4
	Tahoma.SetIconLocation( 53, pTextureHandle,  98,  0, 4,  10) #	 5
	Tahoma.SetIconLocation( 54, pTextureHandle, 103,  0, 4,  10) #	 6
	Tahoma.SetIconLocation( 55, pTextureHandle, 108,  0, 4,  10) #	 7
	Tahoma.SetIconLocation( 56, pTextureHandle, 113,  0, 4,  10) #	 8
	Tahoma.SetIconLocation( 57, pTextureHandle, 118,  0, 4,  10) #	 9
	Tahoma.SetIconLocation( 58, pTextureHandle,   0, 10,   1,  10) #	 :
	Tahoma.SetIconLocation( 59, pTextureHandle,   2, 10,   2,  10) #	 ;
	Tahoma.SetIconLocation( 60, pTextureHandle,   5, 10,  5, 10) #	 <
	Tahoma.SetIconLocation( 61, pTextureHandle,  11, 10,  6, 10) #	 =
	Tahoma.SetIconLocation( 62, pTextureHandle,  18, 10,  5, 10) #	 >
	Tahoma.SetIconLocation( 63, pTextureHandle,  24, 10,  4, 10) #	 ?
	Tahoma.SetIconLocation( 64, pTextureHandle,  29, 10,  8, 10) #	 @
	Tahoma.SetIconLocation( 65, pTextureHandle,  38, 10,  6, 10) #	 A
	Tahoma.SetIconLocation( 66, pTextureHandle,  45, 10,  5, 10) #	 B
	Tahoma.SetIconLocation( 67, pTextureHandle,  51, 10,  6, 10) #	 C
	Tahoma.SetIconLocation( 68, pTextureHandle,  58, 10,  6, 10) #	 D
	Tahoma.SetIconLocation( 69, pTextureHandle,  65, 10,  5, 10) #	 E
	Tahoma.SetIconLocation( 70, pTextureHandle,  71, 10,  5, 10) #	 F
	Tahoma.SetIconLocation( 71, pTextureHandle,  77, 10,  6, 10) #	 G
	Tahoma.SetIconLocation( 72, pTextureHandle,  84, 10,  6, 10) #	 H
	Tahoma.SetIconLocation( 73, pTextureHandle,  91, 10,  3, 10) #	 I
	Tahoma.SetIconLocation( 74, pTextureHandle,  95, 10,  3, 10) #	 J
	Tahoma.SetIconLocation( 75, pTextureHandle,  99, 10, 5, 10) #	 K
	Tahoma.SetIconLocation( 76, pTextureHandle, 105, 10, 4, 10) #	 L
	Tahoma.SetIconLocation( 77, pTextureHandle, 110, 10, 7, 10) #	 M
	Tahoma.SetIconLocation( 78, pTextureHandle, 118, 10, 6, 10) #	 N
	Tahoma.SetIconLocation( 79, pTextureHandle,   0, 20,   7, 10) #	 O
	Tahoma.SetIconLocation( 80, pTextureHandle,   8, 20,  5, 10) #	 P
	Tahoma.SetIconLocation( 81, pTextureHandle,  14, 20,  7, 10) #	 Q
	Tahoma.SetIconLocation( 82, pTextureHandle,  22, 20,  4, 10) #	 R
	Tahoma.SetIconLocation( 83, pTextureHandle,  28, 20,  5, 10) #	 S
	Tahoma.SetIconLocation( 84, pTextureHandle,  34, 20,  5, 10) #	 T
	Tahoma.SetIconLocation( 85, pTextureHandle,  40, 20,  6, 10) #	 U
	Tahoma.SetIconLocation( 86, pTextureHandle,  47, 20,  5, 10) #	 V
	Tahoma.SetIconLocation( 87, pTextureHandle,  53, 20,  9, 10) #	 W
	Tahoma.SetIconLocation( 88, pTextureHandle,  63, 20,  5, 10) #	 X
	Tahoma.SetIconLocation( 89, pTextureHandle,  69, 20,  5, 10) #	 Y
	Tahoma.SetIconLocation( 90, pTextureHandle,  75, 20,  5, 10) #	 Z
	Tahoma.SetIconLocation( 91, pTextureHandle,  81, 20,  3, 10) #	 [
	Tahoma.SetIconLocation( 92, pTextureHandle,  85, 20,  4, 10) #	 \
	Tahoma.SetIconLocation( 93, pTextureHandle,  90, 20,  3, 10) #	 ]
	Tahoma.SetIconLocation( 94, pTextureHandle,  94, 20, 6, 10) #	 ^
	Tahoma.SetIconLocation( 95, pTextureHandle, 101, 20, 5, 10) #	 _
	Tahoma.SetIconLocation( 96, pTextureHandle, 107, 20, 2, 10) #	 `
	Tahoma.SetIconLocation( 97, pTextureHandle, 110, 20, 4, 10) #	 a
	Tahoma.SetIconLocation( 98, pTextureHandle, 115, 20, 5, 10) #	 b
	Tahoma.SetIconLocation( 99, pTextureHandle,   0, 30,   4, 10) #	 c
	Tahoma.SetIconLocation(100, pTextureHandle,   5, 30,  5, 10) #	 d
	Tahoma.SetIconLocation(101, pTextureHandle,  11, 30,  4, 10) #	 e
	Tahoma.SetIconLocation(102, pTextureHandle,  16, 30,  3, 10) #	 f
	Tahoma.SetIconLocation(103, pTextureHandle,  20, 30,  5, 10) #	 g
	Tahoma.SetIconLocation(104, pTextureHandle,  26, 30,  5, 10) #	 h
	Tahoma.SetIconLocation(105, pTextureHandle,  32, 30,  1, 10) #	 i
	Tahoma.SetIconLocation(106, pTextureHandle,  34, 30,  2, 10) #	 j
	Tahoma.SetIconLocation(107, pTextureHandle,  37, 30,  5, 10) #	 k
	Tahoma.SetIconLocation(108, pTextureHandle,  43, 30,  1, 10) #	 l
	Tahoma.SetIconLocation(109, pTextureHandle,  45, 30,  7, 10) #	 m
	Tahoma.SetIconLocation(110, pTextureHandle,  53, 30,  5, 10) #	 n
	Tahoma.SetIconLocation(111, pTextureHandle,  59, 30,  5, 10) #	 o
	Tahoma.SetIconLocation(112, pTextureHandle,  65, 30,  5, 10) #	 p
	Tahoma.SetIconLocation(113, pTextureHandle,  71, 30,  5, 10) #	 q
	Tahoma.SetIconLocation(114, pTextureHandle,  77, 30,  3, 10) #	 r
	Tahoma.SetIconLocation(115, pTextureHandle,  81, 30,  3, 10) #	 s
	Tahoma.SetIconLocation(116, pTextureHandle,  85, 30,  2, 10) #	 t
	Tahoma.SetIconLocation(117, pTextureHandle,  88, 30,  5, 10) #	 u
	Tahoma.SetIconLocation(118, pTextureHandle,  94, 30,  5, 10) #	 v
	Tahoma.SetIconLocation(119, pTextureHandle, 100, 30, 7, 10) #	 w
	Tahoma.SetIconLocation(120, pTextureHandle, 108, 30, 4, 10) #	 x
	Tahoma.SetIconLocation(121, pTextureHandle, 113, 30, 5, 10) #	 y
	Tahoma.SetIconLocation(122, pTextureHandle,   0, 40,   3, 10) #	 z
	Tahoma.SetIconLocation(123, pTextureHandle,   4, 40,   4, 10) #	 {
	Tahoma.SetIconLocation(124, pTextureHandle,   9, 40,  1, 10) #	 |
	Tahoma.SetIconLocation(125, pTextureHandle,  11, 40,  4, 10) #	 }
	Tahoma.SetIconLocation(126, pTextureHandle,  16, 40,  6, 10) #	 ~
	Tahoma.SetIconLocation(130, pTextureHandle,  23, 40,  2, 10) #	 ‚
	Tahoma.SetIconLocation(131, pTextureHandle,  29, 40,  5, 10) #	 ƒ
	Tahoma.SetIconLocation(132, pTextureHandle,  35, 40,  3, 10) #	 "
	Tahoma.SetIconLocation(133, pTextureHandle,  39, 40,  5, 10) #	 …
	Tahoma.SetIconLocation(134, pTextureHandle,  45, 40,  5, 10) #	 †
	Tahoma.SetIconLocation(135, pTextureHandle,  51, 40,  5, 10) #	 ‡
	Tahoma.SetIconLocation(136, pTextureHandle,  57, 40,  3, 10) #	 ˆ
	Tahoma.SetIconLocation(137, pTextureHandle,  61, 40,  13, 10) #	 ‰
	Tahoma.SetIconLocation(138, pTextureHandle,  75, 40,  5, 10) #	 Š
	Tahoma.SetIconLocation(139, pTextureHandle,  81, 40,  3, 10) #	 ‹
	Tahoma.SetIconLocation(140, pTextureHandle,  85, 40,  9, 10) #	 Œ
	Tahoma.SetIconLocation(145, pTextureHandle,  95, 40,  1, 10) #	 '
	Tahoma.SetIconLocation(146, pTextureHandle,  97, 40,  1, 10) #	 '
	Tahoma.SetIconLocation(147, pTextureHandle,  99, 40, 3, 10) #	 "
	Tahoma.SetIconLocation(148, pTextureHandle, 103, 40, 3, 10) #	 "
	Tahoma.SetIconLocation(149, pTextureHandle, 107, 40, 5, 10) #	 o
	Tahoma.SetIconLocation(150, pTextureHandle, 113, 40, 3, 10) #	 -
	Tahoma.SetIconLocation(151, pTextureHandle, 117, 40, 3, 10) #	 -
	Tahoma.SetIconLocation(152, pTextureHandle, 121, 40, 4, 10) #	 ˜
	Tahoma.SetIconLocation(153, pTextureHandle,   0, 40,   8, 10) #	 ™
	Tahoma.SetIconLocation(154, pTextureHandle,   9, 40,  3, 10) #	 š
	Tahoma.SetIconLocation(155, pTextureHandle,  13, 40,  3, 10) #	 ›
	Tahoma.SetIconLocation(156, pTextureHandle,  17, 40,  8, 10) #	 œ
	Tahoma.SetIconLocation(159, pTextureHandle,  26, 40,  5, 10) #	 Ÿ
	Tahoma.SetIconLocation(161, pTextureHandle,  32, 50,  1, 10) #	 ¡
	Tahoma.SetIconLocation(162, pTextureHandle,  34, 50,  4, 10) #	 ¢
	Tahoma.SetIconLocation(163, pTextureHandle,  41, 50,  5, 10) #	 £
	Tahoma.SetIconLocation(164, pTextureHandle,  47, 50,  5, 10) #	 ¤
	Tahoma.SetIconLocation(165, pTextureHandle,  53, 50,  5, 10) #	 ¥
	Tahoma.SetIconLocation(166, pTextureHandle,  59, 50,  1, 10) #	 ¦
	Tahoma.SetIconLocation(167, pTextureHandle,  61, 50,  4, 10) #	 §
	Tahoma.SetIconLocation(168, pTextureHandle,  66, 50,  3, 10) #	 ¨
	Tahoma.SetIconLocation(169, pTextureHandle,  70, 50,  8, 10) #	 ©
	Tahoma.SetIconLocation(170, pTextureHandle,  79, 50,  4, 10) #	 ª
	Tahoma.SetIconLocation(171, pTextureHandle,  84, 50,  3, 10) #	 "
	Tahoma.SetIconLocation(172, pTextureHandle,  88, 50,  6, 10) #	 ¬
	Tahoma.SetIconLocation(174, pTextureHandle,  95, 50, 8, 10) #	 ®
	Tahoma.SetIconLocation(175, pTextureHandle, 104, 50, 6, 10) #	 ¯
	Tahoma.SetIconLocation(177, pTextureHandle, 111, 50, 5, 10) #	 ±
	Tahoma.SetIconLocation(178, pTextureHandle, 117, 50, 3, 10) #	 ²
	Tahoma.SetIconLocation(179, pTextureHandle, 121, 50, 3, 10) #	 ³
	Tahoma.SetIconLocation(180, pTextureHandle, 125, 50, 2, 10) #	 ´
	Tahoma.SetIconLocation(181, pTextureHandle,   0, 60,   5, 10) #	 µ
	Tahoma.SetIconLocation(183, pTextureHandle,   6, 60,   1, 10) #	 ·
	Tahoma.SetIconLocation(184, pTextureHandle,   8, 60,  2, 10) #	 ¸
	Tahoma.SetIconLocation(185, pTextureHandle,  11, 60,  3, 10) #	 ¹
	Tahoma.SetIconLocation(186, pTextureHandle,  15, 60,  4, 10) #	 º
	Tahoma.SetIconLocation(187, pTextureHandle,  21, 60,  2, 10) #	 "
	Tahoma.SetIconLocation(188, pTextureHandle,  24, 60,  8, 10) #	 ¼
	Tahoma.SetIconLocation(189, pTextureHandle,  33, 60,  8, 10) #	 ½
	Tahoma.SetIconLocation(190, pTextureHandle,  42, 60,  9, 10) #	 ¾
	Tahoma.SetIconLocation(191, pTextureHandle,  52, 60,  4, 10) #	 ¿
	Tahoma.SetIconLocation(192, pTextureHandle,  57, 60,  6, 10) #	 À
	Tahoma.SetIconLocation(193, pTextureHandle,  64, 60,  6, 10) #	 Á
	Tahoma.SetIconLocation(194, pTextureHandle,  71, 60,  6, 10) #	 Â
	Tahoma.SetIconLocation(195, pTextureHandle,  78, 60,  6, 10) #	 Ã
	Tahoma.SetIconLocation(196, pTextureHandle,  85, 60,  6, 10) #	 Ä
	Tahoma.SetIconLocation(197, pTextureHandle,  92, 60,  6, 10) #	 Å
	Tahoma.SetIconLocation(198, pTextureHandle,  99, 60, 8, 10) #	 Æ
	Tahoma.SetIconLocation(199, pTextureHandle, 108, 60, 6, 10) #	 Ç
	Tahoma.SetIconLocation(200, pTextureHandle, 115, 60, 5, 10) #	 È
	Tahoma.SetIconLocation(201, pTextureHandle, 121, 60, 5, 10) #	 É
	Tahoma.SetIconLocation(202, pTextureHandle,   0, 70,   5, 10) #	 Ê
	Tahoma.SetIconLocation(203, pTextureHandle,   6, 70,  5, 10) #	 Ë
	Tahoma.SetIconLocation(204, pTextureHandle,  12, 70,  3, 10) #	 Ì
	Tahoma.SetIconLocation(205, pTextureHandle,  16, 70,  3, 10) #	 Í
	Tahoma.SetIconLocation(206, pTextureHandle,  20, 70,  3, 10) #	 Î
	Tahoma.SetIconLocation(207, pTextureHandle,  24, 70,  3, 10) #	 Ï
	Tahoma.SetIconLocation(208, pTextureHandle,  28, 70,  6, 10) #	 Ð
	Tahoma.SetIconLocation(209, pTextureHandle,  35, 70,  6, 10) #	 Ñ
	Tahoma.SetIconLocation(211, pTextureHandle,  42, 70,  7, 10) #	 Ó
	Tahoma.SetIconLocation(212, pTextureHandle,  50, 70,  7, 10) #	 Ô
	Tahoma.SetIconLocation(213, pTextureHandle,  58, 70,  7, 10) #	 Õ
	Tahoma.SetIconLocation(214, pTextureHandle,  66, 70,  7, 10) #	 Ö
	Tahoma.SetIconLocation(215, pTextureHandle,  74, 70,  5, 10) #	 ×
	Tahoma.SetIconLocation(216, pTextureHandle,  80, 70,  7, 10) #	 Ø
	Tahoma.SetIconLocation(217, pTextureHandle,  88, 70,  6, 10) #	 Ù
	Tahoma.SetIconLocation(218, pTextureHandle,  95, 70, 6, 10) #	 Ú
	Tahoma.SetIconLocation(219, pTextureHandle, 102, 70, 6, 10) #	 Û
	Tahoma.SetIconLocation(220, pTextureHandle, 109, 70, 6, 10) #	 Ü
	Tahoma.SetIconLocation(221, pTextureHandle, 116, 70, 5, 10) #	 Ý
	Tahoma.SetIconLocation(222, pTextureHandle, 122, 70, 5, 10) #	 Þ
	Tahoma.SetIconLocation(223, pTextureHandle,   0, 80,   4, 10) #	 ß
	Tahoma.SetIconLocation(224, pTextureHandle,   5, 80,   4, 10) #	 à
	Tahoma.SetIconLocation(225, pTextureHandle,  10, 80,  4, 10) #	 á
	Tahoma.SetIconLocation(226, pTextureHandle,  15, 80,  4, 10) #	 â
	Tahoma.SetIconLocation(227, pTextureHandle,  20, 80,  4, 10) #	 ã
	Tahoma.SetIconLocation(228, pTextureHandle,  25, 80,  4, 10) #	 ä
	Tahoma.SetIconLocation(229, pTextureHandle,  30, 80,  4, 10) #	 å
	Tahoma.SetIconLocation(230, pTextureHandle,  35, 80,  8, 10) #	 æ
	Tahoma.SetIconLocation(231, pTextureHandle,  44, 80,  4, 10) #	 ç
	Tahoma.SetIconLocation(232, pTextureHandle,  49, 80,  4, 10) #	 è
	Tahoma.SetIconLocation(233, pTextureHandle,  54, 80,  4, 10) #	 é
	Tahoma.SetIconLocation(234, pTextureHandle,  59, 80,  4, 10) #	 ê
	Tahoma.SetIconLocation(235, pTextureHandle,  64, 80,  4, 10) #	 ë
	Tahoma.SetIconLocation(236, pTextureHandle,  69, 80,  1, 10) #	 ì
	Tahoma.SetIconLocation(237, pTextureHandle,  71, 80,  2, 10) #	 í
	Tahoma.SetIconLocation(238, pTextureHandle,  74, 80,  2, 10) #	 î
	Tahoma.SetIconLocation(239, pTextureHandle,  77, 80,  2, 10) #	 ï
	Tahoma.SetIconLocation(240, pTextureHandle,  80, 80,  4, 10) #	 ð
	Tahoma.SetIconLocation(241, pTextureHandle,  85, 80,  5, 10) #	 ñ
	Tahoma.SetIconLocation(242, pTextureHandle,  91, 80,  5, 10) #	 ò
	Tahoma.SetIconLocation(243, pTextureHandle,  97, 80, 5, 10) #	 ó
	Tahoma.SetIconLocation(244, pTextureHandle, 103, 80, 5, 10) #	 ô
	Tahoma.SetIconLocation(245, pTextureHandle, 109, 80, 5, 10) #	 õ
	Tahoma.SetIconLocation(246, pTextureHandle, 115, 80, 5, 10) #	 ö
	Tahoma.SetIconLocation(247, pTextureHandle, 121, 80, 5, 10) #	 ÷
	Tahoma.SetIconLocation(248, pTextureHandle,  0, 90,   5, 10) #	 ø
	Tahoma.SetIconLocation(249, pTextureHandle,  6, 90,  5, 10) #	 ù
	Tahoma.SetIconLocation(250, pTextureHandle, 12, 90,  5, 10) #	 ú
	Tahoma.SetIconLocation(251, pTextureHandle, 18, 90,  5, 10) #	 û
	Tahoma.SetIconLocation(252, pTextureHandle, 24, 90,  5, 10) #	 ü
	Tahoma.SetIconLocation(253, pTextureHandle, 30, 90,  5, 10) #	 ý
	Tahoma.SetIconLocation(254, pTextureHandle, 36, 90,  5, 10) #	 þ
	Tahoma.SetIconLocation(255, pTextureHandle, 42, 90,  5, 10) #	 ÿ

	# Set spacing
	Tahoma.SetHorizontalSpacing(2.0)
	Tahoma.SetVerticalSpacing(2.0)
	Tahoma.SetSpaceWidth(6.0)
	Tahoma.SetTabWidth(24.0)

