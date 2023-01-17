#pragma once

#include <iostream>
#include <stacktrace>
#include <algorithm>
#include <map>

template< class type_t >
auto ptr( auto address ) { return ( type_t )address; }

#include "include/pe.hxx"
#include "include/nt.hxx"
#include "include/import/kernel32.hxx"
#include "include/import/advapi32.hxx"
#include "include/import/ntdll.hxx"
#include "include/uti.hxx"
