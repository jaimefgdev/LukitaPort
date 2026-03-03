PORT_RISK: dict[int, str] = {
    21: "high",  23: "high",  25: "high",  110: "high", 139: "high",
    445: "high", 1433: "high", 1521: "high", 1723: "high", 3306: "high",
    3389: "high", 5432: "high", 5900: "high", 6379: "high", 27017: "high",
    22: "medium", 53: "medium", 111: "medium", 135: "medium", 143: "medium",
    8080: "medium", 8888: "medium", 9200: "medium",
    80: "low", 443: "low", 465: "low", 587: "low",
    993: "low", 995: "low", 8443: "low",
}
