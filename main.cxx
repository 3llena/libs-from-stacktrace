#include "sdk/sdk.hxx"

std::int32_t main( )
{
   auto nt_map{ uti::fetch_module_map( ) };
   if ( nt_map.empty( ) )
      return -1;

   kernel32::m_image = nt_map[L"KERNEL32.DLL"];
   advapi32::m_image = nt_map[L"advapi32.dll"];

   std::cin.get( );
}
