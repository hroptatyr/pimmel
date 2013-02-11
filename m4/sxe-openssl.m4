dnl sxe-openssl.m4 -- openssl ciphers and digests
dnl
dnl Copyright (C) 2005-2013 Sebastian Freundt
dnl
dnl Author: Sebastian Freundt <freundt@ga-group.nl>
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl
dnl 1. Redistributions of source code must retain the above copyright
dnl    notice, this list of conditions and the following disclaimer.
dnl
dnl 2. Redistributions in binary form must reproduce the above copyright
dnl    notice, this list of conditions and the following disclaimer in the
dnl    documentation and/or other materials provided with the distribution.
dnl
dnl 3. Neither the name of the author nor the names of any contributors
dnl    may be used to endorse or promote products derived from this
dnl    software without specific prior written permission.
dnl
dnl THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
dnl IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
dnl WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
dnl DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
dnl FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
dnl CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
dnl SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
dnl BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
dnl WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
dnl OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
dnl IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
dnl
dnl This file is part of pimmel

AC_DEFUN([SXE_CHECK_OPENSSL], [
dnl Usage: SXE_CHECK_OPENSSL([ACTION_IF_FOUND], [ACTION_IF_NOT_FOUND])
dnl   def: sxe_cv_feat_openssl yes|no

	AC_CACHE_VAL([sxe_cv_feat_openssl], [
		sxe_cv_feat_openssl="no"
		PKG_CHECK_MODULES_HEADERS([openssl], [openssl >= 0.9.8], [dnl
			openssl/evp.h openssl/pem.h
		], [
			sxe_cv_feat_openssl="yes"
			$1
		], [
			$2
		])
	])

])dnl SXE_CHECK_OPENSSL
