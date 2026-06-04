import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Button,
  ConfirmModal,
  DetailList,
  Drawer,
  EmptyState,
  Field,
  Input,
  Modal,
  PageHeader,
  PaginationControls,
  SurfaceCard,
} from "../components/ui";
import { useAppData } from "../contexts/AppDataContext";
import { buildCommitmentDownloadURL, listCommitmentRecordsPage } from "../lib/api";
import type { CommitmentRecord, PaginatedRecords } from "../types";

export function CommitmentsPage() {
  const navigate = useNavigate();
  const { createCommitmentRecord, deleteCommitmentRecord } = useAppData();
  const [selected, setSelected] = useState<CommitmentRecord | null>(null);
  const [open, setOpen] = useState(false);
  const [keyword, setKeyword] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<PaginatedRecords<CommitmentRecord>>({
    list: [],
    total: 0,
    page: 1,
    pageSize: 10,
    totalPages: 0,
  });
  const [listError, setListError] = useState<string | null>(null);
  const [isListLoading, setIsListLoading] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<CommitmentRecord | null>(null);
  const [namespace, setNamespace] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const loadRows = useCallback(async () => {
    setIsListLoading(true);
    setListError(null);
    try {
      const nextData = await listCommitmentRecordsPage({
        page,
        keyword,
      });
      if (nextData.totalPages > 0 && page > nextData.totalPages) {
        setPage(nextData.totalPages);
        return;
      }
      setData(nextData);
    } catch (err) {
      setListError(err instanceof Error ? err.message : "承诺书记录加载失败");
      setData({
        list: [],
        total: 0,
        page,
        pageSize: 10,
        totalPages: 0,
      });
    } finally {
      setIsListLoading(false);
    }
  }, [keyword, page]);

  useEffect(() => {
    void loadRows();
  }, [loadRows]);

  const rows = data.list;

  const handleCreateCommitment = async () => {
    if (!namespace.trim() || !file) {
      setFormError("namespace 和承诺书 PDF 文件均为必填。");
      return;
    }
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      setFormError("只允许上传 PDF 文件。");
      return;
    }

    setSubmitting(true);
    setFormError(null);
    try {
      await createCommitmentRecord({
        namespace: namespace.trim(),
        file,
      });
      setOpen(false);
      setNamespace("");
      setFile(null);
      await loadRows();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "上传承诺书失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page-container">
      <PageHeader
        kicker="Commitments"
        title="承诺书管理"
        description="按 namespace 查看承诺书记录，文件链接保持清晰可点，不在表格里铺长链接。"
        actions={<Button variant="primary" onClick={() => setOpen(true)}>新增承诺书记录</Button>}
      />

      <SurfaceCard>
        <div className="toolbar">
          <Field label="namespace 搜索">
            <Input
              placeholder="输入 namespace"
              value={keyword}
              onChange={(event) => {
                setKeyword(event.target.value);
                setPage(1);
              }}
            />
          </Field>
        </div>
      </SurfaceCard>

      <SurfaceCard className="data-table-wrap" padded={false}>
        {listError ? (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="承诺书记录加载失败"
              description={listError}
              action={<Button variant="secondary" onClick={() => void loadRows()}>重新加载</Button>}
            />
          </div>
        ) : isListLoading ? (
          <div style={{ padding: 20 }}>
            <EmptyState title="承诺书记录加载中" description="正在同步当前页数据。" />
          </div>
        ) : rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>namespace</th>
                <th>文件名</th>
                <th>文件链接</th>
                <th>更新时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td>
                    <button className="namespace-link table-row-button" onClick={() => navigate(`/namespaces/${item.namespace}`)} type="button">
                      {item.namespace}
                    </button>
                  </td>
                  <td>
                    <button className="table-row-button" onClick={() => setSelected(item)} type="button">
                      {item.fileName}
                    </button>
                  </td>
                  <td>
                    <a className="namespace-link" href={buildCommitmentDownloadURL(item.namespace)}>
                      下载文件
                    </a>
                  </td>
                  <td>{item.updatedAt}</td>
                  <td>
                    <Button variant="ghost" onClick={() => setSelected(item)}>
                      查看
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="当前没有承诺书记录"
              description="可以直接新增一条承诺书记录。"
              action={<Button variant="primary" onClick={() => setOpen(true)}>新增承诺书记录</Button>}
            />
          </div>
        )}
      </SurfaceCard>

      <PaginationControls
        page={page}
        pageSize={data.pageSize}
        total={data.total}
        totalPages={data.totalPages}
        onPageChange={setPage}
      />

      <Drawer
        description="这里展示承诺书记录详情，并提供跳转到 namespace 详情的入口。"
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? selected.namespace : ""}
      >
        {selected ? (
          <>
            <DetailList
              items={[
                { label: "namespace", value: selected.namespace },
                { label: "文件名", value: selected.fileName },
                { label: "更新时间", value: selected.updatedAt },
                {
                  label: "文件链接",
                  value: (
                    <a className="namespace-link" href={buildCommitmentDownloadURL(selected.namespace)}>
                      下载文件
                    </a>
                  ),
                },
              ]}
            />
            <div className="button-row" style={{ marginTop: 20 }}>
              <Button variant="secondary" onClick={() => navigate(`/namespaces/${selected.namespace}`)}>
                查看 namespace 详情
              </Button>
              <Button variant="danger" onClick={() => setPendingDelete(selected)}>
                删除记录
              </Button>
            </div>
          </>
        ) : null}
      </Drawer>

      <Modal
        description="上传 namespace 对应的承诺书 PDF。"
        onClose={() => {
          setOpen(false);
          setFormError(null);
        }}
        open={open}
        title="上传承诺书"
      >
        <div className="panel-stack">
          <Field label="namespace">
            <Input placeholder="例如：prod-finance" value={namespace} onChange={(event) => setNamespace(event.target.value)} />
          </Field>
          <Field label="PDF 文件">
            <Input
              accept=".pdf,application/pdf"
              onChange={(event) => {
                const selectedFile = event.target.files?.[0] ?? null;
                setFile(selectedFile);
                setFormError(null);
              }}
              type="file"
            />
          </Field>
          {file ? (
            <div className="muted-text">
              已选择：{file.name}（{Math.max(1, Math.round(file.size / 1024))} KB）
            </div>
          ) : null}
          {formError ? <div className="muted-text" style={{ color: "#b42318" }}>{formError}</div> : null}
          <div className="button-row">
            <Button variant="primary" onClick={() => void handleCreateCommitment()}>
              {submitting ? "上传中..." : "上传并保存"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setOpen(false);
                setFormError(null);
              }}
            >
              取消
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        description={pendingDelete ? `删除后将从当前前端列表中移除 namespace ${pendingDelete.namespace} 的承诺书记录。` : ""}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          void deleteCommitmentRecord(pendingDelete.namespace).then(() => {
            if (selected?.id === pendingDelete.id) {
              setSelected(null);
            }
            setPendingDelete(null);
            void loadRows();
          });
        }}
        open={Boolean(pendingDelete)}
        title="删除承诺书记录"
      />
    </div>
  );
}
