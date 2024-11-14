import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os 

# print(Pro)
# Sample data
# @app.route('/plot')
def admin_plot(vector,typek,days=1):
    plt.ion()
    if typek == 'pro':
        print('pros')
    folder_path = './static/plots'
    file_name= f'admin{typek}{days}.png'
    file_path = os.path.join(folder_path, file_name)
    # if os.path.exists(file_path):
    #     os.remove(file_path)
    if plt.gca().has_data():
        plt.clf()
    categories = [i[0] for i in vector if i[0]]
    values =[i[1] for i in vector if i[0] ]
    plt.bar(categories, values, color='skyblue')
    plt.title(f" {typek} stats")
    plt.xlabel(f"{typek}")
    plt.ylabel(f"{typek}s req count")
    plt.savefig(file_path)
    # plt.show()
    print('plot created')
    # return render_template('plot.html')
# print(plot())
# plt.show()
# admin_plot('pro',1)