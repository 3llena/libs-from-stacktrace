#pragma once

#include <iostream>
#include <stacktrace>
#include <algorithm>
#include <fstream>
#include <map>

template< class type_t >
auto ptr( auto address ) { return ( type_t )address; }

#include "include/os/pe.hxx"
#include "include/os/nt.hxx"
#include "include/uti.hxx"
#include "include/import/kernel32.hxx"
#include "include/import/advapi32.hxx"
