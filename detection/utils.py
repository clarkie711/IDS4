# detection/utils.py
import geoip2.database
import logging
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)
geoip_reader = None

def get_geoip_reader():
    """Initializes and returns the GeoIP reader instance."""
    global geoip_reader
    if geoip_reader is None:
        if not settings.GEOIP_CITY_DB:
            raise ImproperlyConfigured("GEOIP_CITY_DB setting is not configured in settings.py")
        try:
            logger.info(f"Loading GeoIP City database from: {settings.GEOIP_CITY_DB}")
            geoip_reader = geoip2.database.Reader(settings.GEOIP_CITY_DB)
            logger.info("GeoIP City database loaded successfully.")
        except FileNotFoundError:
            logger.error(f"GeoIP database file not found at {settings.GEOIP_CITY_DB}. Geolocation will not work.")
            # Optional: raise ImproperlyConfigured(...) to halt startup if GeoIP is critical
        except Exception as e:
            logger.error(f"Error loading GeoIP database: {e}")
    return geoip_reader

def get_geoip_data(ip_address):
    """
    Looks up geolocation data for a given IP address.
    Returns a dictionary with 'latitude', 'longitude', 'city', 'country',
    or None if lookup fails or IP is private/invalid.
    """
    reader = get_geoip_reader()
    if not reader or not ip_address:
        return None

    try:
        # Skip private IPs (adjust ranges if needed)
        from ipaddress import ip_address as ipaddr_obj, ip_network
        ip = ipaddr_obj(ip_address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
             # logger.debug(f"Skipping GeoIP lookup for private/reserved IP: {ip_address}")
            return None

        response = reader.city(ip_address)
        data = {
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'city': response.city.name,
            'country_code': response.country.iso_code,
            'country_name': response.country.name,
        }
        # logger.debug(f"GeoIP lookup for {ip_address}: {data}")
        return data
    except geoip2.errors.AddressNotFoundError:
        # logger.warning(f"Address {ip_address} not found in GeoIP database.")
        return None
    except Exception as e:
        logger.error(f"Error during GeoIP lookup for {ip_address}: {e}")
        return None

# Call get_geoip_reader once at startup to attempt loading
# get_geoip_reader() # Optional: Load on module import
