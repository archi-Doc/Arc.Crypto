#!/usr/bin/env python
# -*- coding: utf-8 -*-
# searches for ../results folder, and convert csv to png chart.
import os
import sys
import pathlib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def isLogScale(sr):
    min = sr.min()
    max = sr.max()
    if min < 0.001:
        return False
    if max < 0.001:
        return False
    if (max / min) >= 100:
        return True
    return False

def seriesObjectToFloat(dx, column):
    column_index = dx.columns.get_loc(column)
    for idx in range(len(dx)):
        str = dx.iat[idx, column_index].replace(',', '').strip('"')
        n = str.find(' ')
        dx.iat[idx, column_index] = float(str[:n])
    #dx['Mean'] = dx['Mean'].str.replace(',', '').str.replace(unit2, '').astype(float)
    return dx.astype({column: float})

def processSize(p, df, valueColumn):
    if len(df.groupby('Method')) > 12:
        print('Error: The number of method must be less then 12.', file=sys.stderr)
        return

    # print(df.loc[0, 'Mean'])
    unit = df.loc[0, 'Mean'].split(' ')[1]
    # unit2 = ' ' + unit
    df2 = df[['Method', 'Mean', valueColumn]]
    df2 = seriesObjectToFloat(df2, 'Mean')
    # print(df2)

    customMarkers = ["o", "X", "s", "P", "D", "^", "v", "p", "*", "<", ">", "h"] # max 12
    customDashes = ["", (4, 1.5), (1, 1), (3, 1, 1.5, 1), (5, 1, 1, 1), (5, 1, 2, 1, 2, 1), "", (4, 1.5), (1, 1), (3, 1, 1.5, 1), (5, 1, 1, 1), (5, 1, 2, 1, 2, 1)] # max 12
    ax = sns.lineplot(data=df2, style='Method', x=valueColumn, y='Mean', hue='Method', markers=customMarkers, dashes=customDashes)
    # ax = sns.lineplot(data=df2, style='Method', x=valueColumn, y='Mean', hue='Method', markers=True)
    if isLogScale(df2[valueColumn]):
        ax.set_xscale("log")
        ax.set_yscale("log")
    ax.set_ylabel('Mean ' + '(' + unit + ')')
    
    plt.gcf().autofmt_xdate()
    # plt.show()
    plt.savefig(p.with_suffix('.png'), format = 'png', dpi=300)
    plt.clf()

    return

def show_values_on_bars(axs):
    def _show_on_single_plot(ax):        
        for p in ax.patches:
            _x = p.get_x() + p.get_width() / 2
            _y = p.get_y() + p.get_height()
            value = '{:.2f}'.format(p.get_height())
            ax.text(_x, _y, value, ha="center") 

    if isinstance(axs, np.ndarray):
        for idx, ax in np.ndenumerate(axs):
            _show_on_single_plot(ax)
    else:
        _show_on_single_plot(axs)
    return

def process(p, df):
    # print(df.loc[0, 'Mean'])
    unit = df.loc[0, 'Mean'].split(' ')[1]
    # unit2 = ' ' + unit
    df2 = df[['Method', 'Mean']]
    df2 = seriesObjectToFloat(df2, 'Mean')
    # print(df2)

    ax = sns.barplot(data=df2, x='Method', y='Mean')
    ax.set_ylabel('Mean ' + '(' + unit + ')')
    #ax.set_xticklabels(ax.get_xticklabels(), rotation=5, ha="right")
    show_values_on_bars(ax)

    plt.gcf().autofmt_xdate()
    # plt.show()
    plt.savefig(p.with_suffix('.png'), format = 'png', dpi=300)
    plt.clf()

    return

def processFile(p):
    df = pd.read_csv(p)
    if(len(df) == 0):
        return

    if 'Size' in df.columns:
        processSize(p, df, 'Size')
    elif 'Length' in df.columns:
        processSize(p, df, 'Length')
    else:
        process(p, df)

    return

def processFolder(p):
    flag = p.name == 'results'

    for x in p.iterdir():
        if x.is_dir(): # folder
            processFolder(x)
        else: # file
            if flag and x.suffix.lower() == '.csv': # results folder and csv files.
                processFile(x)
    return

sns.set_style("whitegrid")
sns.set(font_scale=0.8)

path = os.getcwd()
processFolder(pathlib.Path(path).parent)
