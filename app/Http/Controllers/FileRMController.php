<?php

namespace App\Http\Controllers;

use App\Models\FileRekamMedis;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Imagick;

class FileRMController extends Controller
{
    public function index()
    {
        $filerm = FileRekamMedis::get();
        return view('simrs.rekammedis.efile_index', [
            'filerm' => $filerm,
        ]);
    }

    public function create()
    {
        // $file = "2022-10-11_15-57-18.884.tif";
        // $im = new Imagick($file);
        // $im->setImageFormat('PNG');
        // $format = $im->getImageFormat();
        // dd($format);
        // $im_blob =  $im->getImagesBlob();
        // dd($im_blob);
        // echo '<img src="data:image/jpg;base64,' . base64_encode($im_blob) . '" />';

        return view('simrs.rekammedis.scanfile');
    }

    public function store(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "norm" => "required|numeric",
            "nama" => "required",
            // "nomorkartu" => "required|numeric|digits:13",
            // "nik" => "required|numeric|digits:16",
            // "nohp" => "required|numeric",
            // "tanggallahir" => "required",
            "jenisberkas" => "required",
            "namafile" => "required",
            "tanggalscan" => "required",
            "fileurl" => "required",
        ]);
        if ($validator->fails()) {
            return response()->json([
                'metadata' => [
                    'code' => 201,
                    'message' => $validator->errors()->first(),
                ],
            ]);
        }

        FileRekamMedis::create([
            'norm' => $request->norm,
            'nama' => $request->nama,
            'nomorkartu' => $request->nomorkartu,
            'nik' => $request->nik,
            'nohp' => $request->nohp,
            'tanggallahir' => $request->tanggallahir,
            'jenisberkas' => $request->jenisberkas,
            'namafile' => $request->namafile,
            'tanggalscan' => $request->tanggalscan,
            'fileurl' => $request->fileurl,
        ]);

        return response()->json([
            'metadata' => [
                'code' => 200,
                'message' => "E-File RM sudah tersimpan.",
            ],
        ]);
    }

    public function show($id)
    {
        $filerm = FileRekamMedis::find($id);
        return response()->json($filerm);
    }

    public function edit($id)
    {
        //
    }

    public function update(Request $request, $id)
    {
        //
    }

    public function destroy($id)
    {
        //
    }
}
