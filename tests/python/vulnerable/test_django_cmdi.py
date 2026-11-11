def run_command(request):
    command = request.GET.get("cmd")
    os.system(command)

def run_post_command(request):
    command = request.POST.get("cmd")
    os.system(command)
