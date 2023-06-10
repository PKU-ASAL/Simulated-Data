import networkx
from sklearn.neighbors import LocalOutlierFactor
import numpy as np
from gensim.models.doc2vec import Doc2Vec, TaggedDocument


def doc2vec(paths=''):
    # -------
    # Function definition: 'doc2vec()'
    # (1) paragraph embedding to sentence vectors
    # -------
    # Required parameters:
    # (1) 'paths': selected top k rareness paths
    # -------
    # Return: top k sentence vectors
    # -------
    length = max(map(len, paths))
    paths_array = np.asarray([xi + ['None'] * (length - len(xi)) for xi in paths])
    # paths_array = np.asarray([np.asarray(xi) for xi in paths])
    documents = [TaggedDocument(doc, [i]) for i, doc in enumerate(paths_array)]
    model = Doc2Vec(vector_size=100, min_count=2, epochs=40)
    model.build_vocab(documents)
    model.train(documents, total_examples=model.corpus_count, epochs=model.epochs)
    return model.docvecs.vectors


def local_outlier_factor(train='', test=''):
    # -------
    # Function definition: 'local_outlier_factor()'
    # (1) novelty detection with local outlier factor (LOF) algorithm
    # -------
    # Required parameters:
    # (1) 'train': a provenance graph of training data
    # (2) 'test': a provenance graph of testing data
    # -------
    # Return: a list of prediction result of LOF
    # -------
    LOF = LocalOutlierFactor(n_neighbors=20, novelty=True)
    LOF.fit(train)
    return list(LOF.decision_function(test))


def get_ground_truth_paths(g: networkx.Graph, origianl_paths, md5_to_node):
    ground_truth_paths = []
    for path in origianl_paths:
        for i in range(len(path) - 1):
            is_warn = g[path[i]][path[i + 1]]['is_warn']
            if is_warn:
                ground_truth_paths.append(path)
                break
    ground_truth_paths = [[md5_to_node[node] for node in path] for path in ground_truth_paths]
    return ground_truth_paths


def get_metric(ground_truth_paths, detection_paths):
    ground_truth_paths = [str(path) for path in ground_truth_paths]
    gt_count = len(ground_truth_paths)
    detect_count = len(detection_paths)
    hit_count = 0
    hit_paths = []
    false_alarm_paths = []
    for path in detection_paths:
        if str(path) in ground_truth_paths:
            hit_paths.append(path)
            hit_count += 1
        else:
            false_alarm_paths.append(path)
    try:
        recall = hit_count / gt_count
    except:
        recall = 0
    try:
        precision = hit_count / detect_count
    except:
        precision = 0
    return {'gt_count': gt_count, 'hit_count': hit_count, 'detection_count': detect_count,
            'false_alarm_count': len(false_alarm_paths), 'recall': recall,
            'precision': precision}, hit_paths, false_alarm_paths


def trace_back_analysis(g: networkx.Graph, prediction_result, origianl_paths, test_md5_to_node):
    # -------
    # Function definition: 'trace_back_analysis()'
    # (1) trace back and map the prediction result of LOF to original paths
    # -------
    # Required parameters:
    # (1) 'prediction_result': a list of prediction result of LOF
    # (2) 'origianl_paths': selected paths of a provenance graph
    # -------
    # Return: detected suspicious paths
    # -------
    threshold = 0
    outliers = []
    outlier_list = []
    outlier_paths = []
    for score in prediction_result:
        if score < threshold:
            outliers.append(prediction_result.index(score))
    print('Outliers index found=', outliers)
    for index in outliers:
        print('Suspicious path found:', origianl_paths[index])
        outlier_paths.append([test_md5_to_node[node] for node in origianl_paths[index]])

        for i in range(len(origianl_paths[index]) - 1):
            print("e_id", i, i + 1, g[origianl_paths[index][i]][origianl_paths[index][i + 1]]['e_id'])
            outlier_list.append(g[origianl_paths[index][i]][origianl_paths[index][i + 1]]['e_id'])

    return outlier_list, outlier_paths


def trace_back_analysis_log4j(g: networkx.Graph, prediction_result, origianl_paths, test_md5_to_node):
    # -------
    # Function definition: 'trace_back_analysis()'
    # (1) trace back and map the prediction result of LOF to original paths
    # -------
    # Required parameters:
    # (1) 'prediction_result': a list of prediction result of LOF
    # (2) 'origianl_paths': selected paths of a provenance graph
    # -------
    # Return: detected suspicious paths
    # -------
    threshold = 0
    outliers = []
    outlier_list = []
    outlier_paths = []
    for score in prediction_result:
        if score < threshold:
            outliers.append(prediction_result.index(score))
    # print('Outliers index found=', outliers)
    for index in outliers:
        # print('Suspicious path found:', origianl_paths[index])
        outlier_paths.append([test_md5_to_node[node] for node in origianl_paths[index]])
        edge_list = []
        for i in range(len(origianl_paths[index]) - 1):
            # print("e_id", i, i + 1, g[origianl_paths[index][i]][origianl_paths[index][i + 1]]['e_id'])
            edge_list.append(g[origianl_paths[index][i]][origianl_paths[index][i + 1]]['e_id'])
        outlier_list.append(edge_list)
    return outlier_list, outlier_paths
