<?php

namespace App\Http\Controllers;

use App\Models\ICD10;
use Illuminate\Http\Request;

class Icd10Controller extends Controller
{
    public function index(Request $request)
    {
        $icd = ICD10::orWhere('diag', 'LIKE', "%{$request->search}%")
            ->orWhere('nama', 'LIKE', "%{$request->search}%")
            ->orWhere('dtd', 'LIKE', "%{$request->search}%")
            ->paginate();
        return view('simrs.icd10', [
            'icd' => $icd,
            'request' => $request,
        ]);
    }
    public function create()
    {
        //
    }

    public function store(Request $request)
    {
        //
    }

    public function show($id)
    {
        //
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
