def run_command(request):
    command = request.args.get("cmd")
    os.system(command)
