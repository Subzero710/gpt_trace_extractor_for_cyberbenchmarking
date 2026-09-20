from flask import Flask,request
app=Flask(__name__)
@app.get('/')
def index(): return {'echo':request.args.get('q','')}
app.run(host='0.0.0.0',port=5000)
