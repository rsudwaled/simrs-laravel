<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\VclaimBPJSController;
use App\Models\Poliklinik;
use App\Models\PoliklinikDB;
use App\Models\SuratKontrol;
use Carbon\Carbon;
use Illuminate\Http\Request;
use RealRashid\SweetAlert\Facades\Alert;
use Barryvdh\DomPDF\Facade\Pdf;
use Dompdf\Dompdf;
use Illuminate\Support\Facades\Auth;

class VclaimController extends Controller
{
    public function monitoring_pelayanan_peserta(Request $request)
    {
        $response = null;
        $api = new VclaimBPJSController();
        if ($request->nomorkartu) {
            $response = $api->peserta_nomorkartu($request);
        }
        if ($request->nik) {
            $response = $api->peserta_nik($request);
            if (isset($response->response->peserta->noKartu)) {
                $request["nomorkartu"] = $response->response->peserta->noKartu;
            }
        }
        $monitoring = $api->monitoring_pelayanan_peserta($request);

        $rujukan_peserta  = $api->rujukan_peserta($request);
        if ($rujukan_peserta->metaData->code == 200) {
            $rujukan_peserta = $rujukan_peserta->response->rujukan;
        } else {
            $rujukan_peserta = null;
        }

        $rujukan_rs_peserta  = $api->rujukan_rs_peserta($request);
        if ($rujukan_rs_peserta->metaData->code == 200) {
            $rujukan_rs_peserta = $rujukan_rs_peserta->response->rujukan;
        } else {
            $rujukan_rs_peserta = null;
        }

        $request['formatfilter'] = 2;
        $suratkontrols = $api->surat_kontrol_peserta($request);
        if ($suratkontrols->metaData->code == 200) {
            $suratkontrols = $suratkontrols->response->list;
        } else {
            $suratkontrols = null;
        }

        return view('vclaim.monitoring_pelayanan_peserta', [
            'request' => $request,
            'response' => $response,
            'monitoring' => $monitoring,
            'suratkontrols' => $suratkontrols,
            'rujukan_peserta' => $rujukan_peserta,
        ]);
    }
    public function delete_sep($noSep, Request $request)
    {
        $api = new VclaimBPJSController();
        $request['noSep'] = $noSep;
        $response = $api->delete_sep($request);
        if ($response->metaData->code == '200') {
            Alert::success('Success', 'Data berhasil dihapus. ' . $response->metaData->message);
        } else {
            Alert::error('Error', 'Data gagal dihapus. ' .  $response->metaData->message);
        }
        return redirect()->back();
    }
    public function data_surat_kontrol(Request $request)
    {
        $suratkontrols = null;
        $api = new VclaimBPJSController();
        if (isset($request->tanggalsuratkontrol)) {
            $tanggal = explode('-', $request->tanggalsuratkontrol);
            $request['tanggal_awal'] =  Carbon::parse($tanggal[0])->format('Y-m-d');
            $request['tanggal_akhir'] =  Carbon::parse($tanggal[1])->format('Y-m-d');
            // dd();
            try {
                $response = $api->data_surat_kontrol($request);
                $suratkontrols = collect($response->response->list);
            } catch (\Throwable $th) {
                //throw $th;
                Alert::error('Error', 'Error : ' .  $th->getMessage());
                return redirect()->route('vclaim.data_surat_kontrol');
            }
        }
        return view('vclaim.data_surat_kontrol', [
            'request' => $request,
            'suratkontrols' => $suratkontrols,
        ]);
    }
    public function buat_surat_kontrol(Request $request)
    {
        $request->validate([
            'nomorsep_suratkontrol' => 'required',
            'tanggal_suratkontrol' => 'required',
            'kodepoli_suratkontrol' => 'required',
            'kodedokter_suratkontrol' => 'required',
        ]);
        $request['nomorsep'] = $request->nomorsep_suratkontrol;
        $request['tanggalperiksa'] = $request->tanggal_suratkontrol;
        $request['kodepoli'] = $request->kodepoli_suratkontrol;
        $poli = PoliklinikDB::where('kodesubspesialis', $request->kodepoli)->first();
        $request['kodedokter'] = $request->kodedokter_suratkontrol;
        $vclaim = new VclaimBPJSController();
        $sk = $vclaim->insert_rencana_kontrol($request);
        if ($sk->metaData->code == 200) {
            SuratKontrol::create([
                "tglTerbitKontrol" => Carbon::now()->format('Y-m-d'),
                "tglRencanaKontrol" => $sk->response->tglRencanaKontrol,
                "poliTujuan" => $request->kodepoli,
                "namaPoliTujuan" => $poli->namasubspesialis,
                "kodeDokter" => $request->kodedokter,
                "namaDokter" => $sk->response->namaDokter,
                "noSuratKontrol" => $sk->response->noSuratKontrol,
                "namaJnsKontrol" => "Surat Kontrol",
                "noSepAsalKontrol" => $request->nomorsep,
                "noKartu" => $sk->response->noKartu,
                "nama" => $sk->response->nama,
                "kelamin" => $sk->response->kelamin,
                "tglLahir" => $sk->response->tglLahir,
                "user" => Auth::user()->name,
            ]);
            Alert::success('Success', 'Pembuatan Surat Kontrol Berhasil Silahkan tulis nomor surat ini untuk pasien : ' .  $sk->response->noSuratKontrol);
            return redirect()->back();
        } else {
            Alert::error('Error', 'Pembuatan Surat Kontrol Gagal karena ' .  $sk->metaData->message);
            return redirect()->back();
        }
    }
    public function edit_surat_kontrol($id)
    {
        $suratkontrol = SuratKontrol::find($id);
        return response()->json($suratkontrol);
    }
    public function update_surat_kontrol(Request $request)
    {
        $request['user'] = Auth::user()->name;
        $request->validate([
            'nomor_suratkontrol_edit' => 'required',
            'nomorsep_suratkontrol_edit' => 'required',
            'kodedokter_suratkontrol_edit' => 'required',
            'kodepoli_suratkontrol_edit' => 'required',
            'tanggal_suratkontrol_edit' => 'required',
            "user" => "required",

        ]);
        $request['noSuratKontrol'] = $request->nomor_suratkontrol_edit;
        $request['noSEP'] = $request->nomorsep_suratkontrol_edit;
        $request['kodeDokter'] = $request->kodedokter_suratkontrol_edit;
        $request['poliKontrol'] = $request->kodepoli_suratkontrol_edit;
        $request['tglRencanaKontrol'] = $request->tanggal_suratkontrol_edit;
        $vclaim = new VclaimBPJSController();
        $response = $vclaim->surat_kontrol_update($request);
        if ($response->metaData->code == 200) {
            Alert::success('Success', 'Surat Kontrol ' . $request->nomor_suratkontrol_edit . ' berhasil di update.');
        } else {
            Alert::error('Error', 'Surat Kontrol ' . $request->nomor_suratkontrol_edit . ' gagal di update. ' . $response->metaData->message);
        }
        return redirect()->back();
    }
    public function delete_surat_kontrol($noSuratKontrol, Request $request)
    {
        $request['noSuratKontrol'] = $noSuratKontrol;
        $request['user'] = Auth::user()->name;
        $vclaim = new VclaimBPJSController();
        $response = $vclaim->surat_kontrol_delete($request);
        if ($response->metaData->code == '200') {
            Alert::success('Success', 'Data berhasil dihapus. ' . $response->metaData->message);
        } else {
            Alert::error('Error', 'Data gagal dihapus. ' .  $response->metaData->message);
        }
        return redirect()->back();
    }
    public function sep_internal(Request $request)
    {
        $sepinternals = null;
        $api = new VclaimBPJSController();
        if ($request->nomorsep) {
            $request['noSep'] = $request->nomorsep;
            $sepinternals = $api->sep_internal($request);
        }
        return view('vclaim.sep_internal', [
            'request' => $request,
            'sepinternals' => $sepinternals,
        ]);
    }
    public function sep_internal_delete(Request $request)
    {
        $api = new VclaimBPJSController();
        $response = $api->sep_internal_delete($request);
        if ($response->metaData->code == 200) {
            Alert::success('Success', 'Data berhasil dihapus. ' . $response->metaData->message);
        } else {
            Alert::error('Error', 'Data gagal dihapus. ' .  $response->metaData->message);
        }
        return redirect()->back();
    }
}
