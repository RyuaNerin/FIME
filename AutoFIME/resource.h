#pragma once

#ifndef __H__FIME_RESOURCES__
#define __H__FIME_RESOURCES__

#define FIME_DLL_DATA   100

#if _WIN64
#define FIME_ARCH       "64"
#define FIME_DX11       "_dx11"
#else
#define FIME_ARCH       "32"
#define FIME_DX11       ""
#endif

#endif
