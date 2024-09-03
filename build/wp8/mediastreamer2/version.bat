::
:: Copyright (c) 2010-2022 Belledonne Communications SARL.
::
:: This file is part of mediastreamer2 
:: (see https://gitlab.linphone.org/BC/public/mediastreamer2).
::
:: This program is free software: you can redistribute it and/or modify
:: it under the terms of the GNU Affero General Public License as
:: published by the Free Software Foundation, either version 3 of the
:: License, or (at your option) any later version.
::
:: This program is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
:: GNU Affero General Public License for more details.
::
:: You should have received a copy of the GNU Affero General Public License
:: along with this program. If not, see <http://www.gnu.org/licenses/>.
::
@ECHO off

SET gitlog=
FOR /f "delims=" %%a IN ('git log -1 "--pretty=format:%%H" ../../../configure.ac') DO SET gitlog=%%a

IF [%gitlog%] == [] GOTO UnknownGitVersion

FOR /f "delims=" %%a IN ('git describe --always') DO SET gitdescribe=%%a
GOTO End

:UnknownGitVersion
SET gitdescribe=unknown

:End
ECHO #define GIT_VERSION "%gitdescribe%" > gitversion.h


FOR /F "delims=" %%a IN ('findstr /B AC_INIT ..\..\..\configure.ac') DO (
	FOR /F "tokens=1,2,3 delims=[,]" %%1 IN ("%%a") DO (
		ECHO #define MEDIASTREAMER_VERSION "%%3" > mediastreamer-config.h
	)
)
