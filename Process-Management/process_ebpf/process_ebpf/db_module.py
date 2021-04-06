from influxdb import InfluxDBClient

def write2db(datatype,data,client):
    tmp = [{"measurement":None,"tags":{},"fields":{},}]
    tmp[0]["measurement"] = datatype["measurement"]
    for x in datatype['tags']:
        tmp[0]["tags"][x] = getattr(data,x)
    for y in datatype['fields']:
        tmp[0]["fields"][y] = getattr(data,y)
    client.write_points(tmp)
    
def connect2db(db_host, db_port, db_user, db_passwd, db_name):
    return InfluxDBClient(db_host, db_port, db_user, db_passwd, db_name)