"""Геолокация по IP: приватные/невалидные адреса пропускаем без сетевого вызова."""
from app import geo


async def test_geo_skips_private_without_network():
    assert await geo.country_code("10.0.0.1") == ""
    assert await geo.country_code("127.0.0.1") == ""
    assert await geo.country_code("192.168.0.5") == ""
    assert await geo.country_code("169.254.1.1") == ""
